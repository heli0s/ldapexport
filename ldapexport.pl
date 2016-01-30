#!/usr/bin/perl
# ----------------------------------------------------------------------------
# ldapexport	- Exports data from an LDAP directory into supported formats.
#
#		  run 'ldapexport -h' for more information.
#
# v1.5.2 - (C) 2008 Adam Dunn
# ----------------------------------------------------------------------------

use warnings;
#use strict;
use FindBin;
use lib "$FindBin::RealBin/lib";
use Data::Dumper;
use File::Basename;
use File::Path;
use File::Find;
##NOTE: Make sure to install IO-Socket-IP also.
use Net::LDAP;
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );
use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
use POSIX qw/strftime/;
use Fcntl qw(:DEFAULT :flock);
#use Data::Dump qw(dump);
use Text::CSV_XS;
use Time::HiRes;
##NOTE: Make sure to install Crypt::Blowfish also.
use Crypt::CBC;
use MIME::Base64;
use Term::ReadKey;

##### Set error handler #####
$SIG{'INT'}     = 'errorhandler';
$SIG{__DIE__}   = 'errorhandler';

##### Constants #####
my $sep = '/'; $sep = '\\' if ($^O =~ /Win/);		# Directory separator.
my $basename	= dirname($0);						# Current working directory.
my $configFile	= $basename.$sep.'ldapexport.conf';	# Default config file.
my $lockfile	= 'ldapexport.tmp';			# Lockfile.
if (-w '/tmp/'.$lockfile) {
	$lockfile = '/tmp/'.$lockfile;
} else {
	$lockfile    = $basename.$sep.$lockfile;
}
my $lockfile_h;						# Lockfile handle.
my $key;
#my $pager       = $ENV{PAGER} || 'type';		# Help pager.
my $csvBuffer   = ();                                   # Used to buffer CSV files.

# The LDAP maps allow you to process various filters on attribute data.
# These map filter functions to the vairous possible filter handlers.
# To add new filters, build a filter subroutine, and include a mapping for
# it here.
my %filters = (
		"REGEX"         => \&filterRegex,
		"LDAP"          => \&filterLdap,
		"CSV"           => \&filterCsv,
		"STATIC"        => \&filterStatic,
		"CHAIN"         => \&filterChain,
                "JOIN"          => \&filterJoin,
		"AGE"           => \&filterAge,
);
	
##### Get options #####
#open (HELP, "|$pager");
GetOptions(\%args,
                'help|h|?',
                'verbose|v',
                'screen|s',
                'noscreen|w',
                'output|o=s',
                'debug|d',
                'enable|e=s',
                'dryrun|q',
                'config|c=s',
                'nolog|n',
                'genkey|k',
                'encpwd|p',
          ) or pod2usage(2);
#pod2usage(-input => \*DATA, -verbose => 3, -output => \*HELP) if $args{help};
pod2usage(-input => \*DATA, -verbose => 3) if $args{help};
#close (HELP);

##### MAIN  #####

## Load Configuration File
$configFile = $args{'config'} if ($args{'config'});
if (my $err = ReadCfg($configFile)) {
    print(STDERR $err, "\n");
    pod2usage(-input => \*DATA, -verbose => 3);
    #exit(1);
}

## Process encryption key.
&createKey if ($args{'genkey'});
&readKey if (defined $CFG::CFG{'key'}{'file'});
&encPassword if ($args{'encpwd'});

## Print any option inforation.
&teePrint('INFO', "DRYRUN is ENABLED: No write actions will actually take place.\n") if ($args{'dryrun'});
&teePrint('INFO', "CONFIG FILE: $configFile\n", 1);
&teePrint('INFO', "LOGFILE: $CFG::CFG{'log'}{'file'}\n", 1) if (!$args{'nolog'});
&teePrint('INFO', "LOGGING is DISABLED\n", 1) if ($args{'nolog'});
&teePrint('INFO', "DEBUG is ENABLED\n", 1) if ($args{'debug'});
&teePrint('INFO', "\n", 1);

## Obtain a process lock or exit.
exit 1 if (&lock);


## Here we start main work.
# Loop over each output block in our config file.
foreach my $output (keys %{$CFG::CFG{'OutputMaps'}}) {

	if ( (($args{'enable'}) && ($args{'enable'} =~ /^$output$/i)) ||
	   ((defined $CFG::CFG{'OutputMaps'}{$output}{'enabled'}) &&
	   ($CFG::CFG{'OutputMaps'}{$output}{'enabled'} =~ /^true$/i)) ) {

		&teePrint('INFO', "- OUTPUT NAME: ".uc($output)."\n");	
                &teePrint('INFO', "  - Source: ".$CFG::CFG{'OutputMaps'}{$output}{'sourceLdap'}."\n");

                if ($CFG::CFG{'ldapServers'}{$CFG::CFG{'OutputMaps'}{$output}{'sourceLdap'}}{'type'} eq 'ldap') {
                    # Load all the bind/search parameteres.
                    my $ldap = {};		# This will contain information for our LDAP bind.
                    $ldap			= $CFG::CFG{'ldapServers'}{$CFG::CFG{'OutputMaps'}{$output}{'sourceLdap'}};
                    $$ldap{'searchfilter'}	= $CFG::CFG{'OutputMaps'}{$output}{'searchfilter'};
                    $$ldap{'key'}		= $CFG::CFG{'OutputMaps'}{$output}{'key'};
                    $$ldap{'dn'}		= $CFG::CFG{'OutputMaps'}{$output}{'dn'};
                    $$ldap{'page'} = ($CFG::CFG{'OutputMaps'}{$output}{'page'}) ? $CFG::CFG{'OutputMaps'}{$output}{'page'} : $$ldap{'page'};

                    @{$$ldap{attributes}} = ();
                    # Extract the attributes to searh for from our attribute maps.
                    &teePrint('DEBUG', "  - Bind and search parameters:\n" );
                    $$ldap{'attributes'} = &applyAttributeMaps($CFG::CFG{'OutputMaps'}{$output}{'attributeMap'}, undef);
                    push($$ldap{'attributes'}, $$ldap{'key'});  # Ensure key is always included in our search.
                    $Data::Dumper::Indent = 2;

                    #my $tmppass = ($key) ? decryptString($$ldap{'bindpass'}) : $$ldap{'bindpass'};
                    my $tmppass = $$ldap{'bindpass'};
                    $$ldap{'bindpass'} =~ s/./x/g;
                    &teePrint('DEBUG', sprintf "%-5s%s\n", "",Dumper($ldap) );
                    $$ldap{'bindpass'} = $tmppass;

                    # Execute the LDAP query.
                    &teePrint('INFO', "  - Excecuting LDAP query: ".$$ldap{'searchfilter'}."\n");
                    my $start_time = [Time::HiRes::gettimeofday()];

                    # Query raw LDAP data.
                    $$currentDBS{LDAP} = &getLdap($ldap, $CFG::CFG{'OutputMaps'}{$output}{'attributeMap'});

                    $$currentDBS{LDAP}[1]	= 1;  # Set LDAP as the master source.
                    &teePrint("INFO", "  - Loaded ".scalar (keys %{$$currentDBS{LDAP}[0]})." entries in ".Time::HiRes::tv_interval($start_time)."s\n");
                }

                if ($CFG::CFG{'ldapServers'}{$CFG::CFG{'OutputMaps'}{$output}{'sourceLdap'}}{'type'} eq 'csv') {
                    my $csv = {};
                    $csv                    = $CFG::CFG{'ldapServers'}{$CFG::CFG{'OutputMaps'}{$output}{'sourceLdap'}};
                    #$$csv{'key'}            = $CFG::CFG{'OutputMaps'}{$output}{'key'};
                    $$csv{'searchfilter'}   = $CFG::CFG{'OutputMaps'}{$output}{'searchfilter'};
                    $$csv{'name'}           = $CFG::CFG{'OutputMaps'}{$output}{'sourceLdap'};

                    &teePrint('INFO', "  - Performing CSV file query: ".$$csv{'searchfilter'}."\n");
                    my $start_time = [Time::HiRes::gettimeofday()];

                    $$currentDBS{LDAP} = &getCSV($csv);

                    $$currentDBS{LDAP}[1]	= 1;
                    &teePrint("INFO", "  - Loaded ".scalar (keys %{$$currentDBS{LDAP}[0]})." entries in ".Time::HiRes::tv_interval($start_time)."s\n");
                }

                # Apply filters and attribute mappings on raw data.
                &teePrint("INFO", "  - Applying attribute maps and filters...\n");
                foreach (keys $currentDBS->{LDAP}->[0]) {
                        #&teePrint("DEBUG", "    - FOR: ".$$currentDBS{LDAP}[0]{$_}[0]."...\n");
                        $$currentDBS{LDAP}[0]{$_}[1] = &applyAttributeMaps($CFG::CFG{'OutputMaps'}{$output}{'attributeMap'}, $$currentDBS{LDAP}[0]{$_}[1] )
                }

		# Output the results to CSV
		if ((($CFG::CFG{'OutputMaps'}{$output}{'type'} =~ /^csv$/i) || ($args{'output'})) && (!$args{'screen'})){
			my $csvFile = ($args{'output'}) ? $args{'output'} : $CFG::CFG{'OutputMaps'}{$output}{'file'};
			my $keep = 0;
			my $timestamp = 0;
			if ((defined $CFG::CFG{'OutputMaps'}{$output}{'timestamp'}) && 
			   ($CFG::CFG{'OutputMaps'}{$output}{'timestamp'} !~ /^false$/i)) {
				$timestamp = strftime("$CFG::CFG{'OutputMaps'}{$output}{'timestamp'}", localtime);
				$csvFile =~ s/(^.*)\.(.*)/$1$timestamp.$2/;
				if (defined $CFG::CFG{'OutputMaps'}{$output}{'keep'}) {
					$keep = $CFG::CFG{'OutputMaps'}{$output}{'keep'};
				}
			}
			&teePrint("INFO", "  - Writing to CSV file: ".$csvFile."\n");
			printCSV($currentDBS, $CFG::CFG{'OutputMaps'}{$output}{'attributeMap'}, $csvFile) if (! $args{'dryrun'});
			if ($keep > 0) {
				my $pattern = basename($csvFile);
				$pattern =~ s/$timestamp/\.\*/;
				&teePrint("INFO", "  - Cleaning old CSV files.  Keeping up to $keep.\n");
				purgeFiles(dirname($csvFile), $pattern, $keep);
			}
		}
		
		# Output the results to STDOUT.
		if ((($CFG::CFG{'OutputMaps'}{$output}{'type'} =~ /^screen$/i) || ($args{'screen'})) && (!$args{'noscreen'})) {
			&teePrint("INFO", "  - Printing Results to STDOUT...\n");
			printOutput($currentDBS);
		}
	}
}

&unlock;	# Release our filelock.
exit(0);


##### FUNCTIONS #####


### Filter Subs ###
### Filters modify LDAP data to fit with the filter instrunctions on attribute
### maps.  Filters are very simple.  They each take the attribute map expression
### you want a filter for, and the raw LDAP results hash.  Each fitler then returns
### an array ref containing the results for that specific attribute map entry.

# This filter allows you to specify a PERL REGEX as an attribute map.
# It expects the expression in the form of:
# "REGEX:expression:attribute", where "expression" is the REGEX, and "attribute"
# is the LDAP attribute name who's data to execute the REGEX against.
sub filterRegex {
	my $input = shift;		# The individual (raw) attribute map expression.
	my $ldapData = shift;	# A hash reference to the LDAP results for an entry.
	my @filteredData;

        my $regEx = $$input{'expression'};
        my $mapAttr = $$input{'attribute'};                 
	
	if (%{$ldapData}) {
		@filteredData = @{$$ldapData{$mapAttr}} if ($$ldapData{$mapAttr});
                        if ($regEx) {
                        unless (ref($regEx)) {
                                foreach (@filteredData) { eval "$regEx"; }
                        } else {
                                foreach (@filteredData) { foreach my $ex (@$regEx) { eval "$ex"; } }
                        }
                }
	} else {
		push @filteredData, $mapAttr;
	}

	return \@filteredData;
}

# This filter allows you to make an individual separate LDAP query to another
# source.  This can allow for coorelation and extraction of data from multiple sources.
# It expects the expression in the form of:
# "LDAP:source ldap:base dn:key:attribute:value", where "source ldap" is an LDAP server section
# name from the config file, "key" is the attribute to search on, "value" is the attribute
# from the current LDAP source that will be the key value on the seconary LDAP source.  This is
# how mapping occurs.  "base dn" is the search base in the secondary directory, and "attribute"
# is the remote attribute to extract.
# Additionally, the remote attribute is stored in the current ldapData table, so that it
# can be used in future filter calls.  The attribute is prefixed with the source name
# (ie. sourceLdap_remoteAttribute).
sub filterLdap {
	my $input = shift;		# The individual (raw) attribute map expression.
	my $ldapData = shift;	# A hash reference to the LDAP results for an entry.
	my @filteredData;

        my $sourceLdap = $$input{'server'};
        my $ldapBase = $$input{'dn'};
        my $ldapKey = $$input{'searchKey'};
        my $ldapAttr = $$input{'attribute'};
        my $inputValue = $$input{'matchKey'};               

	my @temp = $$ldapData{$inputValue};
	my $keyValue = $temp[0]->[0];

	if (%{$ldapData}) {
		if ($$ldapData{$inputValue}) {
			my $tempLdap = {};
			$tempLdap                   = $CFG::CFG{'ldapServers'}{$sourceLdap};
			$$tempLdap{'searchfilter'}  = "(".$ldapKey."=".$keyValue.")";
			$$tempLdap{'key'}           = $ldapKey;
			$$tempLdap{'dn'}            = $ldapBase;
			$$tempLdap{'page'}          = 0;
			@{$$tempLdap{attributes}} = ();
			push @{$$tempLdap{attributes}}, $ldapKey;
			push @{$$tempLdap{attributes}}, $ldapAttr;

			# Query LDAP for the results.
			my $queryResults = &getLdap($tempLdap);
			my $resultsValue = (values %{$queryResults->[0]})[0]->[1] if ($queryResults);

			@filteredData = @{$$resultsValue{$ldapAttr}} if ($$resultsValue{$ldapAttr});

			# Inject the new value into our ldapData table.  This allows
			# it to be used in other filters form hereon.
			@{$$ldapData{$sourceLdap."_".$ldapAttr}} = @filteredData
		}
	} else {
		# Since the filter is being called without data, return the local
		# attribute name for mapping purposes.
		push @filteredData, $inputValue;
	}
	return \@filteredData;

}

# This filer allows making a sub-search in a separate CSV file for data.  The filter
# is similar to the LDAP filter.
sub filterCsv {
	my $input = shift;		# The individual (raw) attribute map expression.
	my $ldapData = shift;	# A hash reference to the LDAP results for an entry.
	my @filteredData;

        my $sourceCsv = $$input{'source'};
        my $csvKey = $$input{'searchKey'};
        my $csvAttr = $$input{'attribute'};
        my $inputValue = $$input{'matchKey'};               

	my @temp = $$ldapData{$inputValue};
	my $keyValue = $temp[0]->[0];

	if (%{$ldapData}) {
		if ($$ldapData{$inputValue}) {
			my $tempCsv = {};
			$tempCsv                   = $CFG::CFG{'ldapServers'}{$sourceCsv};
                        $$tempCsv{'name'}           = $sourceCsv;
                        if ($csvKey eq $$tempCsv{'key'}) {
                            $$tempCsv{'searchfilter'}  = $$tempCsv{'key'}."=".$keyValue;
                        } else {
                            $$tempCsv{'searchfilter'}  = $csvKey."=/".$keyValue."/i";
                        }
			#$$tempCsv{'key'}           = $csvKey;

			# Query LDAP for the results.
			my $queryResults = &getCSV($tempCsv);
			my $resultsValue = (values %{$queryResults->[0]})[0][1] if (defined $queryResults->[0]);

			@filteredData = @{$$resultsValue{$csvAttr}} if ($$resultsValue{$csvAttr});

			# Inject the new value into our ldapData table.  This allows
			# it to be used in other filters form hereon.
			@{$$ldapData{$sourceCsv."_".$csvAttr}} = @filteredData
		}
	} else {
		# Since the filter is being called without data, return the local
		# attribute name for mapping purposes.
		push @filteredData, $inputValue;
	}
	return \@filteredData;

}

# This filter calculates a person's age based on a DOB attribute (MM/DD/YYYY).
# It expects the expression in the form of:
# "AGE:attribute", where "attribute" contains the person's DOB.
sub filterAge {
	my $input = shift;		# The individual (raw) attribute map expression.
	my $ldapData = shift;	# A hash reference to the LDAP results for an entry.
	my @filteredData;

        my $mapAttr = $input;

	if (%{$ldapData}) {
		if ($$ldapData{$mapAttr}) {
			@filteredData = @{$$ldapData{$mapAttr}};
			foreach (@filteredData) { $_ = &calculateAge($_); }
		}
	} else {
		push @filteredData, $mapAttr;
	}
	return \@filteredData;

}

# This is a static filter.  The purpose of this is to allow you to inject
# static data into an attribute map, rather than pulling it from the a
# directory.
# It expects the expression in the form of:
# "STATIC:value", where "value" is the value you want to inject.
sub filterStatic {
	my $input = shift;		# The individual (raw) attribute map expression.
	my $ldapData = shift;	# A hash reference to the LDAP results for an entry.
	my @filteredData = ();

        if (%{$ldapData}) {
                push @filteredData, $input;
        }

	return \@filteredData;
}


# This is a chain filter.  It allows you to chain one or more other attribute
# maps together.  These can be raw LDAP values or other filters to create
# a fairly powerful compound result.
# It expects the expression in the form of:
# "CHAIN:expression[:CHAIN:expression][:CHAIN:expression][...]", where
# "expression" is an LDAP attribute or other filter.
# An alternate form of CHAIN is CHAINMULTI, which will return an array of
# values from each chain expression.  The default returns only the last value
# of the chain.
sub filterChain {
	my $input = shift;		# The individual (raw) attribute map expression.
	my $ldapData = shift;	# A hash reference to the LDAP results for an entry.
	my @filteredData = (); my @temp;

        my $chainType = (($$input{'return'}) && ($$input{'return'} =~ /multi/i)) ? 'multi' : 'single';
        my $chainLinks = $$input{'list'};

        foreach my $chainLink (@{$chainLinks}) {
		@temp = ();
		if (%{$ldapData}) {
			@temp = @{$$ldapData{$chainLink}} if ($$ldapData{$chainLink});
		} else {
			@temp = ( $chainLink );
		}
		foreach my $filter (keys %filters) {
                        if ($$chainLink{$filter}) {
				my $filter_ref = $filters{$filter};
				@temp = @{&{$filter_ref}($$chainLink{$filter},$ldapData)};
				last;
			}
		}

		if ((! %{$ldapData}) || ($chainType eq "multi")) {
			@filteredData = (@filteredData, @temp);
		} else {	
			@filteredData = @temp;
		}
	}

	return \@filteredData;
}

# This filter will join a multi-valued attribute into a single valued attribute,
# separated by the specified separator character.
sub filterJoin {
	my $input = shift;		# The individual (raw) attribute map expression.
	my $ldapData = shift;	# A hash reference to the LDAP results for an entry.
	my @filteredData = (); my @temp;

        my $separator = $$input{'separator'};;
        my $list = $$input{'list'};

        if (%{$ldapData}) {
                @temp = @{$$ldapData{$list}} if ($$ldapData{$list});
        } else {
                @temp = ( $list );           
        }

        foreach my $filter (keys %filters) {
                if ($$list{$filter}) {
                        my $filter_ref = $filters{$filter};
                        @temp = @{&{$filter_ref}($$list{$filter},$ldapData)};
                        last;
                }
        }

        if (%{$ldapData}) {
                @filteredData = ( join($separator, @temp) );
        } else {	
                @filteredData = (@filteredData, @temp);
        }

	return \@filteredData;
}

## This function acts similar to unix tee.  It is designed to print both to
## stdout and log files.  It has the added awareness of loglevels, meaning
## you feed it the log level, and it determines where to send the output
## based on what the log level setting is.
sub teePrint {
	my $level = shift;	# Log level (ie. warn, error, info...)
	my $output = shift;	# Text to output.
	my $nolog = shift;	# 1 = no logging. ie. just stdout.
	$nolog = 0 if (! $nolog);
	my $stdoutLevel = 'OFF';# Default terminal output level.
	my %logLevels = (	'OFF'	=> 0,
				'ERROR'	=> 1,
				'WARN'	=> 2,
				'INFO'	=> 3,
				'DEBUG'	=> 4 );

	# Handle LOG file output.  Based on config file setting.
	if (($CFG::CFG{'log'}{'level'} !~ /^off$/i) && ($nolog ne 1) && (! $args{'nolog'})) {
		#my $time = strftime('%D %T',localtime);
		my $time = strftime('%Y-%m-%d %H:%M:%S',localtime);
		open LOGFILE, ">>$CFG::CFG{'log'}{'file'}" or die "ERROR: Can't open log file ".$CFG::CFG{'log'}{'file'}.": $!";
		if (($logLevels{uc($CFG::CFG{'log'}{'level'})}) && ($logLevels{$level} le $logLevels{uc($CFG::CFG{'log'}{'level'})})) {
			print LOGFILE $time." ".uc($level)."> ".$output;
		}
		close LOGFILE;
	}

	# Handle terminal output.  Based on command option.
	$stdoutLevel = 'INFO' if ($args{'verbose'});
	$stdoutLevel = 'DEBUG' if ($args{'debug'});
	if (($logLevels{$level}) && ($logLevels{$level} le $logLevels{$stdoutLevel})) {
		print STDOUT $output if ($logLevels{$level} ge 3);
		print STDERR uc($level).": ".$output if (($logLevels{$level} le 2) && ($logLevels{$level} ge 1));
	}
}

# This function simply writes the output results to STDOUT.  Useful for debugging.
sub printOutput {
	$currentDBS = shift;	# Input data. ie. $$ref[0]{user id}[1]{hash of attributes}[0] = value.

	foreach my $entry (values $currentDBS->{LDAP}->[0]) {
		print '-' x 80, "\n";
		foreach (@{$entry->[1]}) {
			foreach my $key (keys %{$_}) {
				printf "%-30s: %s\n", $key, join('|', @{$_->{$key}});
			}
		}
	}
}

# This function simply writes the result output table to a CSV file.
sub printCSV {
	my $currentDBS = shift;	# Input data. ie. $$ref[0]{user id}[1]{hash of attributes}[0] = value.
	my $attributeMap = shift;	# Attribute map from config file.
	my $file = shift;			# Filename to write to.
	my $header = [];
	
	foreach (@{$attributeMap}) { foreach (keys %{$_}) { push $header, $_; } }
	
	my $csv = Text::CSV_XS->new ({ binary => 1, eol => "\n" });
	open my $fh, ">", $file or die $file.": $!";

	$csv->print ($fh, $header);
	
	# Convert data into a sortable format.
	my @rows;
	foreach my $entry (values $currentDBS->{LDAP}->[0]) {
		$row = [];
		foreach (@{$entry->[1]}) {
			foreach my $key (keys %{$_}) {
				push(@$row, join('|', @{$_->{$key}}));
			}
		}
		push (@rows, $row);
	}
	
	# Sort before writing to file.
	my @sorted_rows = sort { $a->[0] cmp $b->[0] } @rows;
	
	# Write rows to file.
	for my $row_ref (@sorted_rows) { $csv->print ($fh, $row_ref) or $csv->error_diag; }
	close $fh or die $file.": $!";

}


# This function serves two purposes.
# (A) if you do not specify $ldapData, it simply returns an array ref of
# all LDAP attributes specified in the config entrie's attribute map.  This
# is useful because attributes can be mixed in with filters.
# (B) if you specify $ldapData, it will actually use the LDAP data to resolve
# each of the attribute map entries and return the results.
sub applyAttributeMaps {
	my $attributeMap = shift;	# An array reference to the attribute map from the config file.
	my $ldapData = shift;		# OPTIONAL: LDAP data results from an entry.
	my @outputData;
	%$ldapData = () if (!$ldapData);
	
	foreach my $map (@{$attributeMap}) {
		my @t = keys %{$map}; my $outputAttr = $t[0];
		my $mapAttr = $$map{$outputAttr};

		my @filteredData = (); my $regEx = '';
		my $appliedFilter = 0;

                if (%$mapAttr) {
                        foreach my $filter (keys %filters) {
                                if ($$mapAttr{$filter}) {
                                        my $filter_ref = $filters{$filter};
                                        @filteredData = @{&{$filter_ref}($$mapAttr{$filter},$ldapData)};
                                        $appliedFilter = 1;
                                        last;
                                }
                        }
                }		
		if (%{$ldapData}) {
                        @filteredData = ($appliedFilter) ? @filteredData : ((map { $_ } @{$$ldapData{$mapAttr}}) ? @{$$ldapData{$mapAttr}} : ());

			my %uniq = map { $_, 1 } @filteredData;
			@filteredData = keys %uniq;
			push(@outputData, {$outputAttr => \@filteredData});
		} else {
			if (! $appliedFilter) {
				if (!$mapAttr) { next; }
				@filteredData = ( $mapAttr );
			}
			my %uniq = map { $_, 1 } @filteredData;
			@filteredData = keys %uniq;
			@outputData = (@outputData, @filteredData);
		}
	}
	
	return \@outputData;
}

sub getCSV {
    my $queryInfo = shift;
    my $rows = ();
    my $rowhr = {};
    my @cols;

    # To speed up multile calls against the same CSV file, we will buffer the file
    # into a hash only on the first load.  Use the CSV's config name as the buffer index.
    if (! $$csvBuffer{$$queryInfo{name}}) {
        
        # Support optional file globs.  If a glob is in the filename, we'll sort
        # the list and only grab the most last.  Useful for date sorting.
        my @files = glob($$queryInfo{file});
        my $latestFile = $$queryInfo{file};
        if (@files) {
            @files = sort {lc($a) cmp lc($b)} @files;
            $latestFile = $files[$#files];
        }

        &teePrint('DEBUG', "    - Loading and buffering CSV file: ".$latestFile."\n");

        # Create object
        my $csv = Text::CSV_XS->new($$queryInfo{csv_opts}) or 
            &teePrint('ERROR', "Cannot load CSV: ".Text::CSV_XS->error_diag()."\n") && die;

        # Open the CSV file.
        open my $fh, "<", $latestFile or die "$latestFile: $!";

        # If we are using headers, extract the first line from the CSV to use.
        if ($$queryInfo{header} eq 'true') {
            @cols = map {(!defined $_) ? 'undefined' : $_ } @{$csv->getline ($fh)};
            #@cols = grep { defined $_ } @{$csv->getline ($fh)};
            $csv->bind_columns (\@{$rowhr}{@cols});
        }

        # Iterate over each line in the CSV to extract the data.
        my $tempHash;
        while (my $row = $csv->getline ($fh)) {
            
            # Prep search filter.
            #my ($searchKey, $searchRegex) = split(/=/, $$queryInfo{searchfilter}, 2);
            #$searchRegex = 'qr'.$searchRegex;

            # There are two types of return data to handle depending on if headers are used,
            # so we handle separately.  This could be better normalized into a common data
            # structure.

            if ($$queryInfo{'header'} eq 'true') {
                # Ignore entries without a valid primary key.
                if (!$rowhr->{$$queryInfo{key}}) { next; }
                # Ignore entries with key values in our exclusion list.
                if (grep(/$rowhr->{$$queryInfo{key}}/,@exclude)) { next; }

                $$tempHash{$rowhr->{$$queryInfo{key}}} = [$rowhr->{$$queryInfo{key}}, {map {$_ => ((defined $_) && (defined $rowhr->{$_})) ? [$rowhr->{$_}] : []} @cols}];
            } else {
                if (!$row->[$$queryInfo{key}]) { next; }
                if (grep(/$row->[$$queryInfo{key}]/,@exclude)) { next; }

                $$tempHash{$row->[$$queryInfo{key}]} = [$row->[$$queryInfo{key}], {map {$_ => (defined $row->[$_]) ? [$row->[$_]] : []} keys @$row}];
            }
        }

        # Handle file load errors.
        my @diag = $csv->error_diag;
        if ($diag[0] != 2012) {  
            &teePrint('ERROR', "CSV PARSE ERROR: ".$diag[0]." - ".$diag[1]." @ row ".$diag[3]." pos ".$diag[2]."\n");
            die;
        }

        # Store this data into our buffer.
        if ($tempHash) {
            push @{$$csvBuffer{$$queryInfo{name}}}, $tempHash;
        }

        close $fh or die "$$queryInfo{file}: $!";
    }

    my $tempBuffer = ();

    # If the file has been buffered, use the buffer to grab our requested data.
    if ($$csvBuffer{$$queryInfo{name}}) {
        # We can match attributes in the CSV buffer in two ways, extact or by search.
        # Search is much slower, but allows you to search on any row of the CSV matrix.
        # Exact match only lets you match on the CSV's primary key.

        # Prep search filter.
        my $searchRegex;
        my ($searchKey, $searchExpression) = split(/=/, $$queryInfo{searchfilter}, 2);
        
        if ($searchExpression =~ m/^m(\/.*)/i) {
            $searchRegex = 'qr'.$1;

            # Search requested.  This is very slow and needs to be optimized.
            foreach my $entryKey (keys $$csvBuffer{$$queryInfo{name}}[0]) {
                foreach my $value (@{$$csvBuffer{$$queryInfo{name}}[0]{$entryKey}[1]{$searchKey}}) {
                    if (($value) && (defined($searchRegex)) && ($value =~ eval $searchRegex )) {
                        $$tempBuffer{$entryKey} = $$csvBuffer{$$queryInfo{name}}[0]{$entryKey};
                    }
                }
            }
        } else {
            # No search requested, so perform an exact match on primary key.
            if (defined $$csvBuffer{$$queryInfo{name}}[0]{$searchExpression}) {
                $$tempBuffer{$searchExpression} = $$csvBuffer{$$queryInfo{name}}[0]{$searchExpression};
            }
        }
    }
#print Dumper $tempBuffer;
    push @{$rows}, $tempBuffer;

    return $rows;
}

sub getLdap {
##### Function to query LDAP and retrieve specified attributes.
# Inputs:
# - LDAP QueryInfo.  Contains hash of all fields needed to run a query.
# Returns:
# - Reference to array of hashes to array of hashes of array.
#   The structure is as such to make it easier for running our diff
#   later.
#       ie. $$ref[0]{user id}[1]{hash of attributes}[0] = value.
#           $$ref[0]{user id}[0] = dn
#####

	my $queryInfo = shift;
	my $attributeMap = shift;
	
	my ($bindstat, $page, $paging, $cookie, $temp);
	my @ldapArgs; my %tempAttrs;

	# Bind and establish our LDAP server connection.
	my $scheme = ($$queryInfo{secure}) ? 'ldaps' : 'ldap';
	my $ldap = Net::LDAP->new($$queryInfo{host}, port => $$queryInfo{port}, scheme => $scheme, verify => 'none') || 
		&teePrint('ERROR', "Error connecting to $$queryInfo{host}: $@\n") && die;
	if ( $$queryInfo{binduser} ) {
                my $bindpass = ($key) ? decryptString($$queryInfo{bindpass}) : $$queryInfo{bindpass};
		$bindstat = $ldap->bind($$queryInfo{binduser}, password => $bindpass);
	} else {
		$bindstat = $ldap->bind;
	}
	if ($bindstat->code) { &teePrint('ERROR', "Bind Error: ".$bindstat->error."\n") && die; };

	@ldapArgs = (   base    => $$queryInfo{dn},
					scope   => "subtree",
					filter  => $$queryInfo{searchfilter},
					attrs   => $$queryInfo{attributes} );

	# Enable Paging.
	# We're doing paging mostly for AD ldap servers.  They typically are limited
	# to 1000 query size limites, however you can exceed that with pages.  This
	# may not work on all LDAP servers.
	if ( $$queryInfo{page} ) {
		$page = Net::LDAP::Control::Paged->new( size => $$queryInfo{page} );
		push(@ldapArgs, control => [ $page ] );
	}

	# Execure LDAP query.
	$pageNum = 1;
	if ( $$queryInfo{page} ) { &teePrint('DEBUG', "  - PAGING set to ".$$queryInfo{page}." entries.\n"); }
	while(1) {
		if ( $$queryInfo{page} ) { &teePrint('DEBUG', "    - Page Number: ".$pageNum."\n"); }
		
		$mesg = $ldap->search( @ldapArgs ); # Run the actual query.
		die $mesg->error if $mesg->code;

		# Loop over each returned LDAP entry.
		foreach my $entry ( $mesg->entries ) {
			if ($entry->get_value($$queryInfo{key})) {
				my %tempAttrs = ();
				my $hashkey = lc($entry->get_value($$queryInfo{key}));
				$hashkey =~ s/\s+//;	# Key should not have any spaces.
				$$temp[0]{$hashkey}[0] = $entry->dn();	# Get the entry base DN.

				foreach my $ldapAttr (@{$$queryInfo{attributes}}) {
					# Load the LDAP attribute value(s).
					$tempAttrs{$ldapAttr} = $entry->get_value( $ldapAttr, asref => 1 );
				}

				# Store the results.
				$$temp[0]{$hashkey}[1] = \%tempAttrs;

				# To run results through the filters while retrieving data, use this.
				# This saves time, but can interfere with the ldap filter, so we abandoned
				# this method.
				#$$temp[0]{$hashkey}[1] = ($attributeMap) ? &applyAttributeMaps($attributeMap, \%tempAttrs) : \%tempAttrs;
			}
		}
		$pageNum = $pageNum + 1;
		
		# Stop if not LDAP_SUCCESS
		$mesg->code and last;

		# Get cookie from paged control.
		my($resp) = $mesg->control( LDAP_CONTROL_PAGED) or last;
		$cookie = $resp->cookie or last;

		# Set cookie in paged control.
		if ( $$queryInfo{page} ) { $page->cookie($cookie); }
	}

	if ($cookie) {
		# An error occurred so tell the server to stop the request.
		$page->cookie($cookie);
		$page->size(0);
		$ldap->search( @ldapArgs );
		&teePrint('ERROR', "LDAP query aborted.") && die;
	}
	
	return $temp;
}

sub purgeFiles {
	my $filePath = shift;
	my $filePattern = shift;
	my $fileCount = shift;

	my %info;
	my $wanted;
	$wanted = sub {
		/$filePattern/ or return;
		-f and $info{-M $File::Find::name}= $File::Find::name;
	};

	find(\&$wanted, $filePath);
	my @files;
	foreach (sort {$a <=> $b} keys %info) {
		push @files, $info{$_};
	}

	my $x=@files;
	while ($x > $fileCount) {
		my $delete = pop @files;
		unlink $delete;
		#print ("DELETE: $delete\n");
		$x--;
	}
}


## This function handles our file lock.  For locking we just create a tmp file with some
## basic process information, and do a flock on it.  This is to prevent an inadvertant
## second itteration of this process from running.
sub lock {
	if (! sysopen($lockfile_h, $lockfile, O_WRONLY | O_CREAT | O_EXCL)) {
		&teePrint('ERROR', "Failure creating $lockfile for locking: $!\n");
		if (open(IN, $lockfile)) {
			my $ctns = join('', <IN>);
			close(IN);
			&teePrint('ERROR', "$ctns");
			&teePrint('ERROR', "my pid: $$\n");
		}
		return 1;
	}

	if (! flock($lockfile_h, LOCK_EX)) {
		&teePrint('ERROR', "flock($lockfile, LOCK_EX) failed: $!\n");
		return 1;
	}

	truncate($lockfile_h, 0);
	my $old_h = select($lockfile_h);
	my $old_bar = $|;
	$| = 1;
	select($old_h);
	$| = $old_bar;
	my $now = localtime(time());
	print $lockfile_h "$$ (ldapexport is running. it is now $now)", "\n";
	return 0;
}

## Removes our file lock.
sub unlock {
	if (! close($lockfile_h)) {
		&teePrint('ERROR', "close($lockfile) failed: $!\n");
		return 1;
	}
	if (unlink($lockfile) != 1) {
		&teePrint('ERROR', "Failed clearing lockfile $lockfile): $!\n");
		return 1;
	}
	return 0;
}


# Read a configuration file
#   The arg can be a relative or full path, or
#   it can be a file located somewhere in @INC.
sub ReadCfg
{
    my $file = $_[0];

    our $err;

    {   # Put config data into a separate namespace
        package CFG;

        # Process the contents of the config file
        my $rc = do($file);

        # Check for errors
        if ($@) {
            $::err = "ERROR: Failure compiling '$file' - $@";
        } elsif (! defined($rc)) {
            $::err = "ERROR: Failure reading '$file' - $!";
        } elsif (! $rc) {
            $::err = "ERROR: Failure processing '$file'";
        }
    }

    return ($err);
}

### Helper function to calculate age based on DOB (MM/DD/YYYY).
sub calculateAge {
	# Assuming $birth_month is 0..11
	my ($birth_month, $birth_day, $birth_year) = split(/\//, shift @_);

	my ($day, $month, $year) = (localtime)[3..5];
	$year += 1900;

	my $age = $year - $birth_year;
	$age-- unless sprintf("%02d%02d", $month+1, $day)
		>= sprintf("%02d%02d", $birth_month, $birth_day);
	return $age;
}

### Encrypts a string
sub encryptString {
        my $string = shift;
  
        my $cipher = Crypt::CBC->new(
            -key        => unpack(chr(ord("a") + 19 + print ""),$key),
            -cipher     => 'Blowfish',
            -padding  => 'space',
            -add_header => 1
        );

        my $enc = $cipher->encrypt( $string  );
        return encode_base64($enc); 
}

### Decrypts a string.
sub decryptString {
        my $string = shift;

        my $cipher = Crypt::CBC->new(
            -key        => unpack(chr(ord("a") + 19 + print ""),$key),
            -cipher     => 'Blowfish',
            -padding  => 'space',
            -add_header => 1
        );

        my $dec = $cipher->decrypt( decode_base64($string) );
        return $dec; 
}

### Interactive utility to encrypt passwords.
sub encPassword {
        if ($key) {
                print "Enter a password to encrypt: ";
                ReadMode( noecho  => STDIN );
                my $pass = <STDIN>;
                ReadMode( restore => STDIN );
                print "\n";
                chomp $pass;
                if ($pass) {
                        my $str = encryptString($pass);
                        print "Encrypted password: ".$str."\n";
                }
        } else {
                print "Encryption not enabled in the config file.\n\n";
                pod2usage(2);
        }
}

### Reads a key file for encryption.
sub readKey {
        if ((defined $CFG::CFG{'key'}{'file'}) && ( -r $CFG::CFG{'key'}{'file'} ) && ( -s $CFG::CFG{'key'}{'file'} )) {
                &teePrint('DEBUG', "  - Opening key file: $CFG::CFG{'key'}{'file'}\n" );

                open my $keyFile, '<', $CFG::CFG{'key'}{'file'} or &teePrint('ERROR', "Problem reading key file.");
                $key = <$keyFile>;
                close $keyFile;
        } else {
                &teePrint('ERROR', "Unable to read key.  You may need to generate a key (option -p).", 1);
                print "Unable to read key.  You may need to generate a key (option -p).\n\n";
                pod2usage(2);
        }
}

### Creates a key file for encryption.
### This key will be obfuscated using the pack command, but not itself encrypted.
sub createKey {
        print "You are about to create a new password key file.\n";
        print "IMPORTANT: The key stored in this file will be used to encrypt/decrypt passwords for\n";
	print "           connected systems.  This key will be obfuscated, but itself not encrypted.  It is\n";
	print "           important to keep this key file as secure as possibile and limit access to it.\n";
	print "\n";
        print "This will overwrite your existing key file.\n";
        print "Continue? [N/y]: ";
        my $input = <STDIN>;
        chomp $input;
        if ($input =~ m/^[Y]$/i) {
                print "\nEnter a random phrase to use as the key: ";
                ReadMode( noecho  => STDIN );
                my $phrase = <STDIN>;
                ReadMode( restore => STDIN );
                print "\n";

                open my $keyFile, '>', $CFG::CFG{'key'}{'file'} or &teePrint('ERROR', "Problem opening key file.") && die;;
                print {$keyFile} pack("u",$phrase);
                close $keyFile; 
        }
        exit(0);
}

### Global error handling function.
sub errorhandler {
	my ($sig) = @_;
	
        # This is a work around for a strange threads error related to IO::Net::SSL I believe.
	# Having a blank message will bypass the error handler.  -AMD
	if ($sig =~ m/.*Can't locate object method "tid" via package "threads".*/) { return; }
	
	if ($sig) { 
		&teePrint('ERROR', "$sig\n");
		&unlock;
		exit(1);
	}
}

#SDG

__DATA__

=head1 NAME

ldapexport -	Exports data from an LDAP directory and/or CSV files into 
                supported formats.  Currently supported formats: CSV, STDOUT.

=head1 SYNOPSIS

ldapexport [OPTIONS]

   ldapexport --help
   ldapexport 
   ldapexport [-vdsqnkp] [-c PATH] [-e NAME] [-o FILE]
   
=head1 OPTIONS

   [PATH]               Output directory to save custom web reports.
                        This is required.

   -h   --help			Long help listing.
   -v   --verbose		Verbose output to terminal.
   -s   --screen		Force output of results ONLY to screen.
   -o   --output [file]         Specify alternate CSV output filename.
   -q   --dryrun		Dryrun.  No write actions will actually happen.
   -e   --enable [name]		Force output section name to enabled.
   -n   --nolog			Disable logging.  Enabled by default.
   -c   --config [file]		Specify an alternate config file.
				Default is ldapexport.conf
   -k   --genkey                Generate a new keyfile for encryption. 
   -p   --encpwd                Encrypt a bind password for use in a configuration.
   -d   --debug			Debug output to terminal (does not affect log level).
				Very detailed.

=head1 DESCRIPTION

B<ldapexport> is a posix LDAP data exporter.  It will read posix LDAP entries,
and export those to a selected format.

Currently supported formats include:

	CSV, SCREEN (STDOUT).

One benefit to B<ldapexport> is the ability to map specific LDAP attributes to
alternate output values, as well as build output filters instead of a one to
one mapping.  For example, you can pass raw LDAP data through a PERL compatible
REGEX filter before outputting the data.  New filters can easily be added by
building new perl subroutines for the desired result.

Currently Available filers:

	REGEX: Pass return value through a PERL REGEX.
	STATIC: Inject a static value.
        LDAP: Make a sub-LDAP query to extract single attributes.
        CSV: Make a sub-query in a CSV file to extract a single attribute.
	CHAIN: Chain multiple expressions.
        JOIN: Join a multi-valued result into a single value with a separator.
        AGE: Calculates an age from a date of birth.

All configuration is done based on a default config file B<ldapexport.conf>
which is searched for in the local path.  All program behavior is determined
from that file.  Please see the default config file for further documentation.

Passwords:

For connection parameters to LDAP servers, passwords may be encrypted so that
they are not stored in clear text.  To encrypt passwords, a key file must be
generated with the --genkey options, that will be used to salt the encrypted
passwords.  This key file should be kept secure.  Passwords can be encrypted
with this key using the --encpwd option.  The encrypted value can then be used
in LDAP server configurations.

=head1 EXAMPLES

   - Execute an export process based on all enabled configuration maps in 
     the configuration file.
   ./ldapexport

   - A typical approach is to keep all configuration maps disabled in the 
     configuration file, and to only execute ones as needed:
   ./ldapexport -e mapping

   - See what would take place, but not actually export.
   ./ldapexport -vdn

