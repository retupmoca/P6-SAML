use XML::Signature;
use UUID;

use Auth::SAML2::Assertion;

class Auth::SAML2::Response;

has $.issuer;
has $.status;
has $.assertion;

has $.signed = False;
has $.signature-valid;
has $.signature-cert;
has $.signature-key;

method parse-xml(XML::Element $xml) {
    $xml.ownerDocument.root.idattr = 'ID';

    my $samlp-prefix = $xml.nsPrefix('urn:oasis:names:tc:SAML:2.0:protocol');
    $samlp-prefix ~= ':' if $samlp-prefix.chars;

    die 'Not a response' unless $xml.name eq $samlp-prefix~'Response';

    for $xml.elements {
        my $saml-prefix = .nsPrefix('urn:oasis:names:tc:SAML:2.0:assertion') || '';
        $saml-prefix ~= ':' if $saml-prefix.chars;
        when .name eq $saml-prefix ~ 'Assertion' {
            $!assertion = Auth::SAML2::Assertion.new;
            $!assertion.parse-xml($_);
        }

        my $sig-prefix = .nsPrefix('http://www.w3.org/2000/09/xmldsig#');
        $sig-prefix ~= ':' if $sig-prefix;
        when .name eq $sig-prefix~'Signature' {
            $!signed = True;
            $!signature-valid = verify($_);
            # XXX TODO: pull out signature cert
        }
    }
}

method Str {
    my $id = UUID.new.Str;
    my $elem = make-xml('samlp:Response', :ID($id), :Version('2.0'), :IssueInstant(DateTime.now.utc.Str), make-xml('saml:Issuer', $.issuer));
    $elem.setNamespace('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp');
    $elem.setNamespace('urn:oasis:names:tc:SAML:2.0:assertion', 'saml');

    # this is...sloppy
    my $str = $elem.Str;
    $str ~~ s/\<\/samlp\:Response\>/{ $.assertion.Str ~ '</samlp:Response>' }/;

    my $xml = from-xml($str);

    if $.signed && $.signature-cert && $.signature-key {
        sign($xml.root, :private-pem($.signature-key), :x509-pem($.signature-cert));
    }

    return $xml.Str;
}
