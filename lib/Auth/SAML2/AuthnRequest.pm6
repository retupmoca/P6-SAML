use XML;
use UUID;
use XML::Signature;

class Auth::SAML2::AuthnRequest;

has $.issuer;

has $.signed;
has $.signature-valid;
has $.signature-cert;
has $.signature-key;

method parse-xml($xml) {
    my $prefix = $xml.nsPrefix('urn:oasis:names:tc:SAML:2.0:protocol');
    $prefix ~= ':' if $prefix;

    die "Not an AuthnRequest" unless $xml.name eq $prefix~'AuthnRequest';

    my $sprefix = $xml.nsPrefix('urn:oasis:names:tc:SAML:2.0:assertion');
    $sprefix ~= ':' if $sprefix;
    $!issuer = $xml.elements($sprefix~'Issuer').contents.join;
}

method Str {
    my $id = UUID.new.Str;
    my $elem = make-xml('samlp:AuthnRequest', :ID($id), :Version('2.0'), :IssueInstant(DateTime.now.utc.Str),
                        make-xml('saml:Issuer', $.issuer),
                        make-xml('samlp:NameIDPolicy', :AllowCreate('true'), :Format('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'));
    $elem.setNamespace('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp');
    $elem.setNamespace('urn:oasis:names:tc:SAML:2.0:assertion', 'saml');

    $xml = from-xml($elem.Str);

    if $.signed && $.signature-cert && $.signature-key {
        sign($xml.root, :private-pem($.signature-key), :x509-pem($.signature-cert));
    }

    return $xml.Str;
}
