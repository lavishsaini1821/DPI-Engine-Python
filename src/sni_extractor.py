class SNIExtractor:
    """
    Extracts Server Name Indication (SNI)
    from TLS packets.
    """

    # TLS record header (5) + handshake header (4)
    # + client version (2) + random (32) = 43 bytes
    # before the session ID length field.
    SESSION_ID_OFFSET = 43

    # Extension type 0x0000 is server_name (SNI).
    EXTENSION_TYPE_SNI = 0x0000

    def extract(self, payload):

        if not payload:
            return None

        # Every offset below is validated against this length.
        # A real capture can be truncated at any byte, so we never
        # trust a length field that the packet itself declares.
        length = len(payload)

        # The record header is 5 bytes and the handshake type sits
        # at byte 5, so we need at least 6 bytes to classify.
        if length < 6:
            return None

        # check if the packet is TLS handshake
        if payload[0] != 0x16:
            return None

        # Check ClientHello
        if payload[5] != 0x01:
            return None

        # Adding OFF-SET Now
        offset = self.SESSION_ID_OFFSET

        # Now we are reading the length of SESSION ID
        if offset >= length:
            return None

        session_id_length = payload[offset]

        # Now we are skipping the SESSION ID
        offset += 1 + session_id_length

        # Reading the CYPHER SUIT length
        if offset + 2 > length:
            return None

        cipher_suite_length = int.from_bytes(
            payload[offset:offset + 2],
            byteorder="big"
        )

        # Now we will skip the CYPHER SUIT length
        offset += 2 + cipher_suite_length

        # Now we will read the COMPRESSION METHOD length
        if offset >= length:
            return None

        compression_method_length = payload[offset]

        # Now we will skip the COMPRESSION METHODS
        offset += 1 + compression_method_length

        # Now we will Read the EXTENSIONS
        if offset + 2 > length:
            return None

        extensions_length = int.from_bytes(
            payload[offset:offset + 2],
            byteorder="big"
        )

        # Now we will skip the EXTENSIONS while making the BOUNDARY line.
        # Clamp to the real payload size so a truncated capture that
        # declares more extension bytes than it carries cannot walk
        # off the end.
        offset += 2
        extensions_end = min(offset + extensions_length, length)

        # Now we wil check the EXTENSION one by one, using While loop
        while offset + 4 <= extensions_end:
            extension_type = int.from_bytes(
                payload[offset:offset + 2],
                byteorder="big"
            )
            extension_length = int.from_bytes(
                payload[offset + 2:offset + 4],
                byteorder="big"
            )

            # Now we will ckeck if the EXTENSION type is SNI or not
            if extension_type == self.EXTENSION_TYPE_SNI:
                sni_offset = offset + 4

                # server_name_list length (2) + name type (1)
                # + host name length (2) = 5 bytes of SNI header.
                if sni_offset + 5 > length:
                    return None

                # Now we will read the SNI data and extract the HOST NAME
                server_name_length = int.from_bytes(
                    payload[sni_offset + 3:sni_offset + 5],
                    byteorder="big"
                )

                name_start = sni_offset + 5
                name_end = name_start + server_name_length

                # The declared host name can run past a truncated capture.
                if name_end > length:
                    return None

                server_name = payload[
                    name_start:name_end
                ].decode(errors="ignore")

                return server_name or None

            offset += 4 + extension_length

        return None
