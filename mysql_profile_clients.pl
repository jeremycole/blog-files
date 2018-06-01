#!/usr/bin/perl

# Command to capture packets this can understand:
#   sudo /usr/sbin/tshark -l -i eth0 -s 4096 -z "proto,colinfo,mysql.query,mysql.query" -z "proto,colinfo,tcp.dstport,tcp.dstport" -z "proto,colinfo,tcp.srcport,tcp.srcport" -a duration:30 port 3306

use strict;
use warnings;
use File::Basename;
use Getopt::Long;
use POSIX;
use Data::Dumper;

my $opt_help            = 0;
my $opt_summary_only    = 0;
my $opt_metrics_by_time = 0;
my $minimum_packets     = undef;
my $maximum_packets     = undef;
my $print_unknown       = 0;

my %options = (
  "help|?"              => \$opt_help,
  "summary_only|s"      => \$opt_summary_only,
  "metrics_by_time|t"   => \$opt_metrics_by_time,
  "minimum_packets|m=i" => \$minimum_packets,
  "maximum_packets|x=i" => \$maximum_packets,
  "print_unknown|u"     => \$print_unknown,
);

sub usage
{
  my $me = basename $0;

  print <<END_OF_HELP;
Usage:
  $me [OPTIONS]

  --help, -?                Print this message

  --summary_only, -s        Only print a final summary
  --metrics_by_time, -t     Print a detailed report with per-second metrics
  --minimum_packets, -m     Minimum packets per client for summarization
  --maximum_packets, -x     Maximum packets per client for summarization
  --print_unknown, -u       Print the request/response for unknown events

END_OF_HELP
}

my $clients = {};

sub parse_packet
{
  my ($line) = @_;
  $line =~ /^[ ]*([0-9.]+)[ ]+([0-9.]+) -> ([0-9.]+)[ ]+(.+)[ ]+tcp.srcport == ([0-9]+)[ ]+tcp.dstport == ([0-9]+)(?:[ ]+mysql.query == ["](.+)["]?)?/
    or return undef;

  my ($time, $src, $dst, $message, $srcport, $dstport, $mysql_query) =
     ($1,    $2,   $3,   $4,       $5,       $6,       $7);

  return {
    "time"      => $time,
    "src"       => $src.":".$srcport,
    "dst"       => $dst.":".$dstport,
    "message"   => $message,
    "query"     => $mysql_query,
  };
}

sub process_data
{
  my $time_start  = undef;
  my $time_finish = undef;

  while(my $line = <STDIN>)
  {
    my $packet = &parse_packet($line);
    next if(!defined($packet) or !defined($packet->{'message'}));

    $time_start  = $packet->{'time'} if(!defined($time_start));
    $time_finish = $packet->{'time'};

    if($packet->{'message'} =~ /MySQL (Server Greeting)/)
    {
      my $client = $packet->{'dst'};
      my $type = "tx:" . $1;
      $clients->{$client}->{'packets'}++;
      $clients->{$client}->{'count'}->{$type}++;
      next;
    }

    if($packet->{'message'} =~ /MySQL (Login Request|Request.*)/)
    {
      my $client = $packet->{'src'};
      my $type = "rx:" . $1;
      $clients->{$client}->{'packets'}++;
      $clients->{$client}->{'count'}->{$type}++;
      $clients->{$client}->{'request'} = $packet;

      next if(!defined($clients->{$client}->{'response'}));
      my $time = $clients->{$client}->{'request'}->{'time'}
                  - $clients->{$client}->{'response'}->{'time'};

      my $period = int($clients->{$client}->{'request'}->{'time'});

      push @{$clients->{$client}->{'times'}->{$period}->{'idle'}}, $time if ($time > 0);
      $clients->{$client}->{'response'} = undef;
      next;
    }

    if($packet->{'message'} =~ /(MySQL Response|TCP \[TCP segment of a reassembled PDU\])/)
    {
      my $client = $packet->{'dst'};
      my $type = "tx:Response " . (($1 eq "MySQL Response") ? "Complete" : "Partial") ;
      $clients->{$client}->{'packets'}++;
      $clients->{$client}->{'count'}->{$type}++;
      $clients->{$client}->{'response'} = $packet;

      next if(!defined($clients->{$client}->{'request'}));
      my $time = $clients->{$client}->{'response'}->{'time'}
                  - $clients->{$client}->{'request'}->{'time'};

      my $period = int($clients->{$client}->{'request'}->{'time'});

      my $busy_key = "busy_unknown";
      if(defined($clients->{$client}->{'request'}->{'query'}))
      {
        # Capture the first three words into $1, $2, $3
        if($clients->{$client}->{'request'}->{'query'} =~ /^(?:\s|[\(\)])*([a-zA-Z]+)(?:\s+?([^ "]+))?(?:\s+?([^ "]+))?/)
        {
          my $busy_command = lc($1);
          if($busy_command eq 'handler')
          {
            # Construct the full handler command name, slightly shortened
            $busy_command = "ha_" . lc($3);
          }
          $busy_key = ("busy_" . $busy_command);
        }
      }

      if($clients->{$client}->{'request'}->{'message'} =~ /MySQL Request (Prepare|Execute|Close) Statement/)
      {
        $busy_key = ("busy_" . lc($1));
      }

      if($print_unknown and $busy_key eq "busy_unknown")
      {
        print "Unknown event from client $client!\n";
        print "Request: ";
        print Dumper $clients->{$client}->{'request'};
        print "Response: ";
        print Dumper $clients->{$client}->{'response'};
        print "\n";
      }

      push @{$clients->{$client}->{'times'}->{$period}->{$busy_key}}, $time if ($time > 0);
      $clients->{$client}->{'request'} = undef;
      next;
    }
  }

  return $time_finish - $time_start;
}

sub find_count_sum_min_max_avg_std_nth
{
  my ($data_aref_aref, $nth_aref) = @_;

  my $count = 0;
  my $sum = 0;
  my $min = undef;
  my $max = undef;

  foreach my $data_aref (@{$data_aref_aref})
  {
    foreach my $data (@{$data_aref})
    {
      $count++;
      $sum += $data;
      $min = $data if(!defined($min) or $data < $min);
      $max = $data if(!defined($max) or $data > $max);
    }
  }

  my $avg = ($count==0)?undef:($sum/$count);

  my $std_sum = 0;
  foreach my $data_aref (@{$data_aref_aref})
  {
    foreach my $data (@{$data_aref})
    {
      $std_sum += ($data - $avg)**2;
    }
  }
  my $std = sqrt($std_sum / $count);

  my @nth;
  if(defined($nth_aref))
  {
    my @unsorted_data;
    foreach my $data_aref (@{$data_aref_aref})
    {
      push @unsorted_data, @{$data_aref};
    }
    my @sorted_data = sort {$a <=> $b} @unsorted_data;
    foreach my $nth (@{$nth_aref})
    {
      my $index = floor($count*$nth)-1;
      push @nth, ($count==0)?undef:($sorted_data[$index]);
    }
  }

  return ($count, $sum, $min, $max, $avg, $std, @nth);
}

sub summarize_clients_aref
{
  my ($clients_name, $clients_aref, $capture_time) = @_;

  my $count_clients = 0;
  my $count_packets = 0;
  my $count_types = {};
  my $times_types = {};

  foreach my $client (@{$clients_aref})
  {
    next if (defined($minimum_packets) and $client->{'packets'} < $minimum_packets);
    next if (defined($maximum_packets) and $client->{'packets'} > $maximum_packets);
    next if (!defined($client->{'times'}));

    $count_clients += 1;
    $count_packets += $client->{'packets'} if defined($client->{'packets'});
    foreach my $count_type (keys %{$client->{'count'}})
    {
      $count_types->{$count_type} += $client->{'count'}->{$count_type};
    }
    foreach my $period (sort keys %{$client->{'times'}})
    {
      foreach my $times_type (keys %{$client->{'times'}->{$period}})
      {
        push @{$times_types->{$times_type}->{"summary"}},
          $client->{'times'}->{$period}->{$times_type};

        if($opt_metrics_by_time)
        {
          push @{$times_types->{$times_type}->{sprintf("%8i", $period)}},
            $client->{'times'}->{$period}->{$times_type};
        }
      }
    }
  }

  return if ($count_packets == 0);
  printf("%s (%d packets%s)\n",
    $clients_name,
    $count_packets,
    $count_clients>1?
      sprintf(", %d client%s", $count_clients, $count_clients==1?"":"s"):
      "",
  );

  printf("\n  Packet types:\n");
  if((scalar keys %{$count_types}) == 0)
  {
    print "    (Unavailable or unknown types.)\n";
  } else {
    printf("    %-35s%10s%10s\n", "", "count", "count/s");
    foreach my $count_type (sort keys %{$count_types})
    {
      printf("    %-35s%10d%10.2f\n",
        $count_type,
        $count_types->{$count_type},
        $count_types->{$count_type}/$capture_time,
      );
    }
  }

  printf("\n  Metrics:\n");
  if((scalar keys %{$times_types}) == 0)
  {
    print "    (Unavailable due to packet ordering or incorrect types.)\n";
  } else {
    printf("    %8s  %-16s%10s%10s%12s%10s%10s%10s%10s%10s%10s%10s%10s\n",
      "time", "type", "events", "events/s", "sum", "min", "max", "avg", "std", "95th", "99th", "99.9th", "99.99th");

    foreach my $times_type (sort keys %{$times_types})
    {
      my $buckets = (scalar keys %{$times_types->{$times_type}}) - 1;
      foreach my $bucket (sort keys %{$times_types->{$times_type}})
      {
        my ($count, $sum, $min, $max, $avg, $std, $p95, $p99, $p999, $p9999) =
          find_count_sum_min_max_avg_std_nth(
            $times_types->{$times_type}->{$bucket},
            [0.95, 0.99, 0.999, 0.9999]
          );
        my $count_s = ($count/$capture_time) * (($bucket eq "summary") ? 1 : $buckets);
        printf("    %8s  %-16s%10.0f%10.2f%12.3f%10.6f%10.6f%10.6f%10.6f%10.6f%10.6f%10.6f%10.6f\n",
          $bucket, $times_type, $count, $count_s, $sum, $min, $max, $avg, $std, $p95, $p99, $p999, $p9999);
      }
    }
  }

  printf("\n");
}

sub summarize_clients
{
  my ($capture_time) = @_;
  my $total_aref = [];
  foreach my $client (sort keys %{$clients})
  {
    push @{$total_aref}, $clients->{$client};

    if(!$opt_summary_only)
    {
      &summarize_clients_aref("Client $client", [$clients->{$client}], $capture_time);
    }
  }
  &summarize_clients_aref(
    sprintf("Summary [%0.2f seconds]", $capture_time),
    $total_aref,
    $capture_time
  );
}

sub main
{
  Getopt::Long::Configure("bundling");
  GetOptions(%options)
    or &usage and exit 1;

  if($opt_help)
  {
    &usage();
    exit(0);
  }

  my $capture_time = &process_data;
  &summarize_clients($capture_time);
}

&main;
