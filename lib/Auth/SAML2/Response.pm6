use Auth::SAML2::Assertion;
class Auth::SAML2::Response;

has $.issuer;
has $.status;
has $.assertion;

has $.signed = False;

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
    }
}
