use XML;

class Auth::SAML2::EntityDescriptor;

has $.entity-id;

has $.organization-name;
has $.organization-display-name;
has %.organization-contact;
has $.organization-url;

has $.x509-pem;

has %.single-sign-on-service;

has %.assertion-consumer-service;

method parse-xml($xml) {
    my $prefix = $xml.nsPrefix('urn:oasis:names:tc:SAML:2.0:metadata');
    $prefix ~= ':' if $prefix;

    die "Not an EntityDescriptor" unless $xml.name eq $prefix~'EntityDescriptor';

    $!entity-id = $xml.attribs<entityID>;

    my $organization = $xml.elements(:TAG($prefix~'Organization'), :SINGLE);
    if $organization {
        $!organization-name = $organization.elements(:TAG($prefix~'OrganizationName'), :SINGLE) ??
                              $organization.elements(:TAG($prefix~'OrganizationName'), :SINGLE).contents.join !!
                              '';

        $!organization-display-name = $organization.elements(:TAG($prefix~'OrganizationDisplayName'), :SINGLE) ??
                                      $organization.elements(:TAG($prefix~'OrganizationDisplayName'), :SINGLE).contents.join !!
                                      '';

        $!organization-url = $organization.elements(:TAG($prefix~'OrganizationURL'), :SINGLE) ??
                             $organization.elements(:TAG($prefix~'OrganizationURL'), :SINGLE).contents.join !!
                             '';
    }
    my $contact = $xml.elements(:TAG($prefix~'ContactPerson'), :SINGLE);
    if $contact {
        %!organization-contact<SurName>      = $contact.elements(:TAG($prefix~'SurName'), :SINGLE).?contents.?join;
        %!organization-contact<EmailAddress> = $contact.elements(:TAG($prefix~'EmailAddress'), :SINGLE).?contents.?join;
    }

    my $idp = $xml.elements(:TAG($prefix~'IDPSSODescriptor'), :SINGLE);
    if $idp {
        my @keys = $idp.elements(:TAG($prefix~'KeyDescriptor'));
        for @keys {
            if .attribs<use> eq 'signing' {
                # XXX
                $!x509-pem = .elements(:TAG($prefix~'KeyInfo'), :SINGLE)\
                             .elements(:TAG($prefix~'KeyName'), :SINGLE).contents.join;
            }
        }

        my @sso = $idp.elements(:TAG($prefix~'SingleSignOnService'));
        for @sso {
            %!single-sign-on-service{.attribs<Binding>.subst(/^urn\:oasis\:names\:tc\:SAML\:2\.0\:bindings\:/, '')} = .attribs<Location>;
        }
    }

    my $sp = $xml.elements(:TAG($prefix~'SPSSODescriptor'), :SINGLE);
    if $sp {
        my @keys = $sp.elements(:TAG($prefix~'KeyDescriptor'));
        for @keys {
            if .attribs<use> eq 'signing' {
                # XXX
                $!x509-pem = .elements(:TAG($prefix~'KeyInfo'), :SINGLE)\
                             .elements(:TAG($prefix~'KeyName'), :SINGLE).contents.join;
            }
        }

        my @acs = $idp.elements(:TAG($prefix~'AssertionConsumerService'));
        for @acs {
            %!assertion-consumer-service{.attribs<Binding>.subst(/^urn\:oasis\:names\:tc\:SAML\:2\.0\:bindings\:/, '')} = .attribs<Location>;
        }
    }
}

method Str {
    my $xml = make-xml('md:EntityDescriptor', :entityID($.entity-id));
    $xml.setNamespace('urn:oasis:names:tc:SAML:2.0:metadata', 'md');

    my $org = make-xml('md:Organization',
                       make-xml('md:OrganizationName', $.organization-name),
                       make-xml('md:OrganizationDisplayName', $.organization-display-name),
                       make-xml('md:OrganizationURL', $.organization-url));
    $xml.append($org);

    if %.single-sign-on-service {
        my $idp = make-xml('md:IDPSSODescriptor');
        for %.single-sign-on-service.kv -> $k, $v {
            $idp.append(make-xml('md:SingleSignOnService', :Binding('urn:oasis:names:tc:SAML:2.0:bindings:'~$k), :Location($v)));
        }
        $xml.append($idp);
    }

    if %.assertion-consumer-service {
        my $sp = make-xml('md:SPSSODescriptor');
        for %.assertion-consumer-service.kv -> $k, $v {
            $sp.append(make-xml('md:AssertionConsumerService', :Binding('urn:oasis:names:tc:SAML:2.0:bindings:'~$k), :Location($v)));
        }
        $xml.append($sp);
    }

    return ~$xml;
}
