use XML::Signature;
use Auth::SAML2::Assertion;

class Auth::SAML2::Response;

has $.issuer;
has $.status;
has $.assertion;

has $.signed = False;
has $.signature-valid;

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
