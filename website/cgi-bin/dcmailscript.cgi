#!/usr/bin/perl

print "Content-type: text/html\n\n";

read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
@pairs = split(/&/, $buffer);foreach $pair (@pairs)
{ 
   ($name, $value) = split(/=/, $pair);
    $value =~ tr/+/ /;
    $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
    $FORM{$name} = $value;
}

if((!$FORM{TOA} && !$FORM{TOG} && !$FORM{TOR})
   || !$FORM{NAME}
   || !$FORM{EMAIL}
   || !$FORM{MESSAGE})
{
	print "<HTML><TITLE>contact</TITLE><BODY>\n";
	print "<A HREF=\"/dc/contact.html\">Try again</A>, cretin.\n";
	print "</BODY></HTML>\n";
	exit 0;
}

if("$FORM{TOA}" eq "Alex")
{
	$to="alx___w2\@hotmail.com";
}

if("$FORM{TOG}" eq "Graham")
{
	if (defined($to))
	{
		$to="$to, keeling\@spamcop.net";
	}
	else
	{
		$to="keeling\@spamcop.net"
	}
}

if("$FORM{TOR}" eq "Richard")
{
	if (defined($to))
	{
		$to="$to, dick_goolez\@hotmail.com";
	}
	else
	{
		$to="dick_goolez\@hotmail.com";
	}
}

open(MAILER, "| /usr/lib/sendmail $to") || die "can't open sendmail";
print MAILER "To: $to\n";
print MAILER "From: $FORM{EMAIL}\n";
print MAILER "Subject: Die Curious message\n\n";
print MAILER "To: $to\n";
print MAILER "Name: $FORM{NAME}\n";
print MAILER "Email: $FORM{EMAIL}\n\n";
print MAILER "$FORM{MESSAGE}\n";
print MAILER "\n\n-------FORM DATA--------\n";

foreach $key (sort keys(%ENV)) {
	print MAILER "$key = $ENV{$key}\n";
}
close(MAILER);

print "<HTML><TITLE>contact</TITLE><BODY>\n";
print "Mail has been sent.<BR>\n";
print "Return to <A HREF=\"/dc/birth.html\">Die Curious</A>.\n";
print "</BODY></HTML>\n";

exit 0;
