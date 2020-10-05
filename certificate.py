class Certificate(Sequence):
    _fields = [
        ('tbs_certificate', TbsCertificate),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature_value', OctetBitString),
    ]

    _processed_extensions = False
    _critical_extensions = None
    _subject_directory_attributes_value = None
    _key_identifier_value = None
    _key_usage_value = None
    _subject_alt_name_value = None
    _issuer_alt_name_value = None
    _basic_constraints_value = None
    _name_constraints_value = None
    _crl_distribution_points_value = None
    _certificate_policies_value = None
    _policy_mappings_value = None
    _authority_key_identifier_value = None
    _policy_constraints_value = None
    _freshest_crl_value = None
    _inhibit_any_policy_value = None
    _extended_key_usage_value = None
    _authority_information_access_value = None
    _subject_information_access_value = None
    _private_key_usage_period_value = None
    _tls_feature_value = None
    _ocsp_no_check_value = None
    _issuer_serial = None
    _authority_issuer_serial = False
    _crl_distribution_points = None
    _delta_crl_distribution_points = None
    _valid_domains = None
    _valid_ips = None
    _self_issued = None
    _self_signed = None
    _sha1 = None
    _sha256 = None

    def _set_extensions(self):
        """
        Sets common named extensions to private attributes and creates a list
        of critical extensions
        """

        self._critical_extensions = set()

        for extension in self['tbs_certificate']['extensions']:
            name = extension['extn_id'].native
            attribute_name = '_%s_value' % name
            if hasattr(self, attribute_name):
                setattr(self, attribute_name, extension['extn_value'].parsed)
            if extension['critical'].native:
                self._critical_extensions.add(name)

        self._processed_extensions = True

    @property
    def critical_extensions(self):
        """
        Returns a set of the names (or OID if not a known extension) of the
        extensions marked as critical
        :return:
            A set of unicode strings
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._critical_extensions

    @property
    def private_key_usage_period_value(self):
        """
        This extension is used to constrain the period over which the subject
        private key may be used
        :return:
            None or a PrivateKeyUsagePeriod object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._private_key_usage_period_value

    @property
    def subject_directory_attributes_value(self):
        """
        This extension is used to contain additional identification attributes
        about the subject.
        :return:
            None or a SubjectDirectoryAttributes object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._subject_directory_attributes_value

    @property
    def key_identifier_value(self):
        """
        This extension is used to help in creating certificate validation paths.
        It contains an identifier that should generally, but is not guaranteed
        to, be unique.
        :return:
            None or an OctetString object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._key_identifier_value

    @property
    def key_usage_value(self):
        """
        This extension is used to define the purpose of the public key
        contained within the certificate.
        :return:
            None or a KeyUsage
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._key_usage_value

    @property
    def subject_alt_name_value(self):
        """
        This extension allows for additional names to be associate with the
        subject of the certificate. While it may contain a whole host of
        possible names, it is usually used to allow certificates to be used
        with multiple different domain names.
        :return:
            None or a GeneralNames object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._subject_alt_name_value

    @property
    def issuer_alt_name_value(self):
        """
        This extension allows associating one or more alternative names with
        the issuer of the certificate.
        :return:
            None or an x509.GeneralNames object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._issuer_alt_name_value

    @property
    def basic_constraints_value(self):
        """
        This extension is used to determine if the subject of the certificate
        is a CA, and if so, what the maximum number of intermediate CA certs
        after this are, before an end-entity certificate is found.
        :return:
            None or a BasicConstraints object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._basic_constraints_value

    @property
    def name_constraints_value(self):
        """
        This extension is used in CA certificates, and is used to limit the
        possible names of certificates issued.
        :return:
            None or a NameConstraints object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._name_constraints_value

    @property
    def crl_distribution_points_value(self):
        """
        This extension is used to help in locating the CRL for this certificate.
        :return:
            None or a CRLDistributionPoints object
            extension
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._crl_distribution_points_value

    @property
    def certificate_policies_value(self):
        """
        This extension defines policies in CA certificates under which
        certificates may be issued. In end-entity certificates, the inclusion
        of a policy indicates the issuance of the certificate follows the
        policy.
        :return:
            None or a CertificatePolicies object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._certificate_policies_value

    @property
    def policy_mappings_value(self):
        """
        This extension allows mapping policy OIDs to other OIDs. This is used
        to allow different policies to be treated as equivalent in the process
        of validation.
        :return:
            None or a PolicyMappings object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._policy_mappings_value

    @property
    def authority_key_identifier_value(self):
        """
        This extension helps in identifying the public key with which to
        validate the authenticity of the certificate.
        :return:
            None or an AuthorityKeyIdentifier object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._authority_key_identifier_value

    @property
    def policy_constraints_value(self):
        """
        This extension is used to control if policy mapping is allowed and
        when policies are required.
        :return:
            None or a PolicyConstraints object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._policy_constraints_value

    @property
    def freshest_crl_value(self):
        """
        This extension is used to help locate any available delta CRLs
        :return:
            None or an CRLDistributionPoints object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._freshest_crl_value

    @property
    def inhibit_any_policy_value(self):
        """
        This extension is used to prevent mapping of the any policy to
        specific requirements
        :return:
            None or a Integer object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._inhibit_any_policy_value

    @property
    def extended_key_usage_value(self):
        """
        This extension is used to define additional purposes for the public key
        beyond what is contained in the basic constraints.
        :return:
            None or an ExtKeyUsageSyntax object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._extended_key_usage_value

    @property
    def authority_information_access_value(self):
        """
        This extension is used to locate the CA certificate used to sign this
        certificate, or the OCSP responder for this certificate.
        :return:
            None or an AuthorityInfoAccessSyntax object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._authority_information_access_value

    @property
    def subject_information_access_value(self):
        """
        This extension is used to access information about the subject of this
        certificate.
        :return:
            None or a SubjectInfoAccessSyntax object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._subject_information_access_value

    @property
    def tls_feature_value(self):
        """
        This extension is used to list the TLS features a server must respond
        with if a client initiates a request supporting them.
        :return:
            None or a Features object
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._tls_feature_value

    @property
    def ocsp_no_check_value(self):
        """
        This extension is used on certificates of OCSP responders, indicating
        that revocation information for the certificate should never need to
        be verified, thus preventing possible loops in path validation.
        :return:
            None or a Null object (if present)
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._ocsp_no_check_value

    @property
    def signature(self):
        """
        :return:
            A byte string of the signature
        """

        return self['signature_value'].native

    @property
    def signature_algo(self):
        """
        :return:
            A unicode string of "rsassa_pkcs1v15", "rsassa_pss", "dsa", "ecdsa"
        """

        return self['signature_algorithm'].signature_algo

    @property
    def hash_algo(self):
        """
        :return:
            A unicode string of "md2", "md5", "sha1", "sha224", "sha256",
            "sha384", "sha512", "sha512_224", "sha512_256"
        """

        return self['signature_algorithm'].hash_algo

    @property
    def public_key(self):
        """
        :return:
            The PublicKeyInfo object for this certificate
        """

        return self['tbs_certificate']['subject_public_key_info']

    @property
    def subject(self):
        """
        :return:
            The Name object for the subject of this certificate
        """

        return self['tbs_certificate']['subject']

    @property
    def issuer(self):
        """
        :return:
            The Name object for the issuer of this certificate
        """

        return self['tbs_certificate']['issuer']

    @property
    def serial_number(self):
        """
        :return:
            An integer of the certificate's serial number
        """

        return self['tbs_certificate']['serial_number'].native

    @property
    def key_identifier(self):
        """
        :return:
            None or a byte string of the certificate's key identifier from the
            key identifier extension
        """

        if not self.key_identifier_value:
            return None

        return self.key_identifier_value.native

    @property
    def issuer_serial(self):
        """
        :return:
            A byte string of the SHA-256 hash of the issuer concatenated with
            the ascii character ":", concatenated with the serial number as
            an ascii string
        """

        if self._issuer_serial is None:
            self._issuer_serial = self.issuer.sha256 + b':' + str_cls(self.serial_number).encode('ascii')
        return self._issuer_serial

    @property
    def not_valid_after(self):
        """
        :return:
            A datetime of latest time when the certificate is still valid
        """
        return self['tbs_certificate']['validity']['not_after'].native

    @property
    def not_valid_before(self):
        """
        :return:
            A datetime of the earliest time when the certificate is valid
        """
        return self['tbs_certificate']['validity']['not_before'].native

    @property
    def authority_key_identifier(self):
        """
        :return:
            None or a byte string of the key_identifier from the authority key
            identifier extension
        """

        if not self.authority_key_identifier_value:
            return None

        return self.authority_key_identifier_value['key_identifier'].native

    @property
    def authority_issuer_serial(self):
        """
        :return:
            None or a byte string of the SHA-256 hash of the isser from the
            authority key identifier extension concatenated with the ascii
            character ":", concatenated with the serial number from the
            authority key identifier extension as an ascii string
        """

        if self._authority_issuer_serial is False:
            akiv = self.authority_key_identifier_value
            if akiv and akiv['authority_cert_issuer'].native:
                issuer = self.authority_key_identifier_value['authority_cert_issuer'][0].chosen
                # We untag the element since it is tagged via being a choice from GeneralName
                issuer = issuer.untag()
                authority_serial = self.authority_key_identifier_value['authority_cert_serial_number'].native
                self._authority_issuer_serial = issuer.sha256 + b':' + str_cls(authority_serial).encode('ascii')
            else:
                self._authority_issuer_serial = None
        return self._authority_issuer_serial

    @property
    def crl_distribution_points(self):
        """
        Returns complete CRL URLs - does not include delta CRLs
        :return:
            A list of zero or more DistributionPoint objects
        """

        if self._crl_distribution_points is None:
            self._crl_distribution_points = self._get_http_crl_distribution_points(self.crl_distribution_points_value)
        return self._crl_distribution_points

    @property
    def delta_crl_distribution_points(self):
        """
        Returns delta CRL URLs - does not include complete CRLs
        :return:
            A list of zero or more DistributionPoint objects
        """

        if self._delta_crl_distribution_points is None:
            self._delta_crl_distribution_points = self._get_http_crl_distribution_points(self.freshest_crl_value)
        return self._delta_crl_distribution_points

    def _get_http_crl_distribution_points(self, crl_distribution_points):
        """
        Fetches the DistributionPoint object for non-relative, HTTP CRLs
        referenced by the certificate
        :param crl_distribution_points:
            A CRLDistributionPoints object to grab the DistributionPoints from
        :return:
            A list of zero or more DistributionPoint objects
        """

        output = []

        if crl_distribution_points is None:
            return []

        for distribution_point in crl_distribution_points:
            distribution_point_name = distribution_point['distribution_point']
            if distribution_point_name is VOID:
                continue
            # RFC 5280 indicates conforming CA should not use the relative form
            if distribution_point_name.name == 'name_relative_to_crl_issuer':
                continue
            # This library is currently only concerned with HTTP-based CRLs
            for general_name in distribution_point_name.chosen:
                if general_name.name == 'uniform_resource_identifier':
                    output.append(distribution_point)

        return output

    @property
    def ocsp_urls(self):
        """
        :return:
            A list of zero or more unicode strings of the OCSP URLs for this
            cert
        """

        if not self.authority_information_access_value:
            return []

        output = []
        for entry in self.authority_information_access_value:
            if entry['access_method'].native == 'ocsp':
                location = entry['access_location']
                if location.name != 'uniform_resource_identifier':
                    continue
                url = location.native
                if url.lower().startswith(('http://', 'https://', 'ldap://', 'ldaps://')):
                    output.append(url)
        return output

    @property
    def valid_domains(self):
        """
        :return:
            A list of unicode strings of valid domain names for the certificate.
            Wildcard certificates will have a domain in the form: *.example.com
        """

        if self._valid_domains is None:
            self._valid_domains = []

            # For the subject alt name extension, we can look at the name of
            # the choice selected since it distinguishes between domain names,
            # email addresses, IPs, etc
            if self.subject_alt_name_value:
                for general_name in self.subject_alt_name_value:
                    if general_name.name == 'dns_name' and general_name.native not in self._valid_domains:
                        self._valid_domains.append(general_name.native)

            # If there was no subject alt name extension, and the common name
            # in the subject looks like a domain, that is considered the valid
            # list. This is done because according to
            # https://tools.ietf.org/html/rfc6125#section-6.4.4, the common
            # name should not be used if the subject alt name is present.
            else:
                pattern = re.compile('^(\\*\\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$')
                for rdn in self.subject.chosen:
                    for name_type_value in rdn:
                        if name_type_value['type'].native == 'common_name':
                            value = name_type_value['value'].native
                            if pattern.match(value):
                                self._valid_domains.append(value)

        return self._valid_domains

    @property
    def valid_ips(self):
        """
        :return:
            A list of unicode strings of valid IP addresses for the certificate
        """

        if self._valid_ips is None:
            self._valid_ips = []

            if self.subject_alt_name_value:
                for general_name in self.subject_alt_name_value:
                    if general_name.name == 'ip_address':
                        self._valid_ips.append(general_name.native)

        return self._valid_ips

    @property
    def ca(self):
        """
        :return;
            A boolean - if the certificate is marked as a CA
        """

        return self.basic_constraints_value and self.basic_constraints_value['ca'].native

    @property
    def max_path_length(self):
        """
        :return;
            None or an integer of the maximum path length
        """

        if not self.ca:
            return None
        return self.basic_constraints_value['path_len_constraint'].native

    @property
    def self_issued(self):
        """
        :return:
            A boolean - if the certificate is self-issued, as defined by RFC
            5280
        """

        if self._self_issued is None:
            self._self_issued = self.subject == self.issuer
        return self._self_issued

    @property
    def self_signed(self):
        """
        :return:
            A unicode string of "no" or "maybe". The "maybe" result will
            be returned if the certificate issuer and subject are the same.
            If a key identifier and authority key identifier are present,
            they will need to match otherwise "no" will be returned.
            To verify is a certificate is truly self-signed, the signature
            will need to be verified. See the certvalidator package for
            one possible solution.
        """

        if self._self_signed is None:
            self._self_signed = 'no'
            if self.self_issued:
                if self.key_identifier:
                    if not self.authority_key_identifier:
                        self._self_signed = 'maybe'
                    elif self.authority_key_identifier == self.key_identifier:
                        self._self_signed = 'maybe'
                else:
                    self._self_signed = 'maybe'
        return self._self_signed

    @property
    def sha1(self):
        """
        :return:
            The SHA-1 hash of the DER-encoded bytes of this complete certificate
        """

        if self._sha1 is None:
            self._sha1 = hashlib.sha1(self.dump()).digest()
        return self._sha1

    @property
    def sha1_fingerprint(self):
        """
        :return:
            A unicode string of the SHA-1 hash, formatted using hex encoding
            with a space between each pair of characters, all uppercase
        """

        return ' '.join('%02X' % c for c in bytes_to_list(self.sha1))

    @property
    def sha256(self):
        """
        :return:
            The SHA-256 hash of the DER-encoded bytes of this complete
            certificate
        """

        if self._sha256 is None:
            self._sha256 = hashlib.sha256(self.dump()).digest()
        return self._sha256

    @property
    def sha256_fingerprint(self):
        """
        :return:
            A unicode string of the SHA-256 hash, formatted using hex encoding
            with a space between each pair of characters, all uppercase
        """

        return ' '.join('%02X' % c for c in bytes_to_list(self.sha256))

    def is_valid_domain_ip(self, domain_ip):
        """
        Check if a domain name or IP address is valid according to the
        certificate
        :param domain_ip:
            A unicode string of a domain name or IP address
        :return:
            A boolean - if the domain or IP is valid for the certificate
        """



        if not isinstance(domain_ip, str_cls):
            raise TypeError(unwrap(
                '''
                domain_ip must be a unicode string, not %s
                ''',
                type_name(domain_ip)
            ))

        encoded_domain_ip = domain_ip.encode('idna').decode('ascii').lower()

        is_ipv6 = encoded_domain_ip.find(':') != -1
        is_ipv4 = not is_ipv6 and re.match('^\\d+\\.\\d+\\.\\d+\\.\\d+$', encoded_domain_ip)
        is_domain = not is_ipv6 and not is_ipv4

        # Handle domain name checks
        if is_domain:
            if not self.valid_domains:
                return False

            domain_labels = encoded_domain_ip.split('.')

            for valid_domain in self.valid_domains:
                encoded_valid_domain = valid_domain.encode('idna').decode('ascii').lower()
                valid_domain_labels = encoded_valid_domain.split('.')

                # The domain must be equal in label length to match
                if len(valid_domain_labels) != len(domain_labels):
                    continue

                if valid_domain_labels == domain_labels:
                    return True

                is_wildcard = self._is_wildcard_domain(encoded_valid_domain)
                if is_wildcard and self._is_wildcard_match(domain_labels, valid_domain_labels):
                    return True

            return False

        # Handle IP address checks
        if not self.valid_ips:
            return False

        family = socket.AF_INET if is_ipv4 else socket.AF_INET6
        normalized_ip = inet_pton(family, encoded_domain_ip)

        for valid_ip in self.valid_ips:
            valid_family = socket.AF_INET if valid_ip.find('.') != -1 else socket.AF_INET6
            normalized_valid_ip = inet_pton(valid_family, valid_ip)

            if normalized_valid_ip == normalized_ip:
                return True

        return False

    def _is_wildcard_domain(self, domain):
        """
        Checks if a domain is a valid wildcard according to
        https://tools.ietf.org/html/rfc6125#section-6.4.3
        :param domain:
            A unicode string of the domain name, where any U-labels from an IDN
            have been converted to A-labels
        :return:
            A boolean - if the domain is a valid wildcard domain
        """

        # The * character must be present for a wildcard match, and if there is
        # most than one, it is an invalid wildcard specification
        if domain.count('*') != 1:
            return False

        labels = domain.lower().split('.')

        if not labels:
            return False

        # Wildcards may only appear in the left-most label
        if labels[0].find('*') == -1:
            return False

        # Wildcards may not be embedded in an A-label from an IDN
        if labels[0][0:4] == 'xn--':
            return False

        return True

    def _is_wildcard_match(self, domain_labels, valid_domain_labels):
        """
        Determines if the labels in a domain are a match for labels from a
        wildcard valid domain name
        :param domain_labels:
            A list of unicode strings, with A-label form for IDNs, of the labels
            in the domain name to check
        :param valid_domain_labels:
            A list of unicode strings, with A-label form for IDNs, of the labels
            in a wildcard domain pattern
        :return:
            A boolean - if the domain matches the valid domain
        """

        first_domain_label = domain_labels[0]
        other_domain_labels = domain_labels[1:]

        wildcard_label = valid_domain_labels[0]
        other_valid_domain_labels = valid_domain_labels[1:]

        # The wildcard is only allowed in the first label, so if
        # The subsequent labels are not equal, there is no match
        if other_domain_labels != other_valid_domain_labels:
            return False

        if wildcard_label == '*':
            return True

        wildcard_regex = re.compile('^' + wildcard_label.replace('*', '.*') + '$')
        if wildcard_regex.match(first_domain_label):
            return True

        return False