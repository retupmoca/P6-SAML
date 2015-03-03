use XML;
use XML::Signature;

class Auth::SAML2::Assertion;

has $.issuer;
has $.subject;
has $.conditions;
has $.authnstatement;
has %.attributes;

has $.signed = False;
has $.signature-valid = False;
has $.signature-cert;

method parse-xml(XML::Element $xml) {
    $xml.ownerDocument.root.idattr = 'ID';

    my $saml-prefix = $xml.nsPrefix('urn:oasis:names:tc:SAML:2.0:assertion');
    $saml-prefix ~= ':' if $saml-prefix.chars;

    die 'Not an assertion' unless $xml.name eq $saml-prefix~'Assertion';

    for $xml.elements {
        when .name eq $saml-prefix~'Issuer' {
            $!issuer = .contents.join;
        }
        when .name eq $saml-prefix~'Subject' {
            $!subject<NameID> = .elements(:TAG($saml-prefix~'NameID'), :SINGLE).contents.join;
        }
        when .name eq $saml-prefix~'Conditions' {
            $!conditions<NotBefore> = DateTime.new($_.attribs<NotBefore>.subst(/\.\d+Z?$/, ''));
            $!conditions<NotOnOrAfter> = DateTime.new($_.attribs<NotOnOrAfter>.subst(/\.\d+Z?$/, ''));
        }
        when .name eq $saml-prefix~'AuthnStatement' {
            $!authnstatement<AuthnInstant> = .attribs<AuthnInstant>;
        }
        when .name eq $saml-prefix~'AttributeStatement' {
            for .elements(:TAG($saml-prefix~'Attribute')) -> $attribute {
                for $attribute.elements(:TAG($saml-prefix~'AttributeValue')) -> $val {
                    %!attributes{$attribute.attribs<FriendlyName> || $attribute.attribs<Name>}.push: $val.contents.join;
                }
            }
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
