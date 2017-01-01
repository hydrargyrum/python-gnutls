
"""GNUTLS crypto support"""

__all__ = ['X509Name', 'X509Certificate', 'X509PrivateKey', 'X509Identity', 'X509CRL', 'DHParams',
           'AEADCipher', 'Cipher']

import re
from ctypes import *

from gnutls.validators import method_args, one_of
from gnutls.constants import X509_FMT_DER, X509_FMT_PEM
from gnutls.errors import *

from gnutls.library.constants import GNUTLS_SAN_DNSNAME, GNUTLS_SAN_RFC822NAME, GNUTLS_SAN_URI
from gnutls.library.constants import GNUTLS_SAN_IPADDRESS, GNUTLS_SAN_OTHERNAME, GNUTLS_SAN_DN
from gnutls.library.constants import GNUTLS_E_SHORT_MEMORY_BUFFER
from gnutls.library.types     import *
from gnutls.library.functions import *


class X509NameMeta(type):
    long_names = {'country': 'C',
                  'state': 'ST',
                  'locality': 'L',
                  'common_name': 'CN',
                  'organization': 'O',
                  'organization_unit': 'OU',
                  'email': 'EMAIL'}
    def __new__(cls, name, bases, dic):
        instance = type.__new__(cls, name, bases, dic)
        instance.ids = X509NameMeta.long_names.values()
        for long_name, short_name in X509NameMeta.long_names.items():
            ## Map a long_name property to the short_name attribute
            cls.add_property(instance, long_name, short_name)
        return instance
    def add_property(instance, name, short_name):
        setattr(instance, name, property(lambda self: getattr(self, short_name, None)))


class X509Name(str):
    __metaclass__ = X509NameMeta

    def __init__(self, dname):
        str.__init__(self)
        pairs = [x.replace('\,', ',') for x in re.split(r'(?<!\\),\s*', dname)]
        for pair in pairs:
            try:
                name, value = pair.split('=', 1)
            except ValueError:
                raise ValueError("Invalid X509 distinguished name: %s" % dname)
            str.__setattr__(self, name, value)
        for name in X509Name.ids:
            if not hasattr(self, name):
                str.__setattr__(self, name, None)
    def __setattr__(self, name, value):
        if name in X509Name.ids:
            raise AttributeError("can't set attribute")
        str.__setattr__(self, name, value)


class AlternativeNames(object):
    __slots__ = {'dns': GNUTLS_SAN_DNSNAME, 'email': GNUTLS_SAN_RFC822NAME, 'uri': GNUTLS_SAN_URI,
                 'ip': GNUTLS_SAN_IPADDRESS, 'other': GNUTLS_SAN_OTHERNAME, 'dn': GNUTLS_SAN_DN}
    def __init__(self, names):
        object.__init__(self)
        for name, key in self.__slots__.iteritems():
            setattr(self, name, tuple(names.get(key, ())))


class X509Certificate(object):

    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_crt_deinit
        instance._c_object = gnutls_x509_crt_t()
        instance._alternative_names = None
        return instance

    @method_args(str, one_of(X509_FMT_PEM, X509_FMT_DER))
    def __init__(self, buf, format=X509_FMT_PEM):
        gnutls_x509_crt_init(byref(self._c_object))
        data = gnutls_datum_t(cast(c_char_p(buf), POINTER(c_ubyte)), c_uint(len(buf)))
        gnutls_x509_crt_import(self._c_object, byref(data), format)

    def __del__(self):
        self.__deinit(self._c_object)

    @property
    def subject(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        try:
            gnutls_x509_crt_get_dn(self._c_object, dname, byref(size))
        except MemoryError:
            dname = create_string_buffer(size.value)
            gnutls_x509_crt_get_dn(self._c_object, dname, byref(size))
        return X509Name(dname.value)

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        try:
            gnutls_x509_crt_get_issuer_dn(self._c_object, dname, byref(size))
        except MemoryError:
            dname = create_string_buffer(size.value)
            gnutls_x509_crt_get_issuer_dn(self._c_object, dname, byref(size))
        return X509Name(dname.value)

    @property
    def alternative_names(self):
        if self._alternative_names is not None:
            return self._alternative_names
        names = {}
        size = c_size_t(256)
        alt_name = create_string_buffer(size.value)
        for i in xrange(65536):
            try:
                name_type = gnutls_x509_crt_get_subject_alt_name(self._c_object, i, alt_name, byref(size), None)
            except RequestedDataNotAvailable:
                break
            except MemoryError:
                alt_name = create_string_buffer(size.value)
                name_type = gnutls_x509_crt_get_subject_alt_name(self._c_object, i, alt_name, byref(size), None)
            names.setdefault(name_type, []).append(alt_name.value)
        self._alternative_names = AlternativeNames(names)
        return self._alternative_names

    @property
    def serial_number(self):
        size = c_size_t(1)
        serial = c_ulong()
        try:
            gnutls_x509_crt_get_serial(self._c_object, cast(byref(serial), c_void_p), byref(size))
        except MemoryError:
            import struct, sys
            serial = create_string_buffer(size.value * sizeof(c_void_p))
            gnutls_x509_crt_get_serial(self._c_object, cast(serial, c_void_p), byref(size))
            pad = size.value * sizeof(c_void_p) - len(serial.value)
            format = '@%dL' % size.value
            numbers = list(struct.unpack(format, serial.value + pad*'\x00'))
            if sys.byteorder == 'little':
                numbers.reverse()
            number = 0
            offset = sizeof(c_void_p) * 8
            for n in numbers:
                number = (number<<offset) + n
            return number
        else:
            return serial.value

    @property
    def activation_time(self):
        return gnutls_x509_crt_get_activation_time(self._c_object)

    @property
    def expiration_time(self):
        return gnutls_x509_crt_get_expiration_time(self._c_object)

    @property
    def version(self):
        return gnutls_x509_crt_get_version(self._c_object)

    #@method_args(X509Certificate)
    def has_issuer(self, issuer):
        """Return True if the certificate was issued by the given issuer, False otherwise."""
        if not isinstance(issuer, X509Certificate):
            raise TypeError("issuer must be an X509Certificate object")
        return bool(gnutls_x509_crt_check_issuer(self._c_object, issuer._c_object))

    @method_args(str)
    def has_hostname(self, hostname):
        """Return True if the hostname matches the DNSName/IPAddress subject alternative name extension
           of this certificate, False otherwise."""
        ## For details see http://www.ietf.org/rfc/rfc2459.txt, section 4.2.1.7 Subject Alternative Name
        return bool(gnutls_x509_crt_check_hostname(self._c_object, hostname))

    def check_issuer(self, issuer):
        """Raise CertificateError if certificate was not issued by the given issuer"""
        if not self.has_issuer(issuer):
            raise CertificateError("certificate issuer doesn't match")

    def check_hostname(self, hostname):
        """Raise CertificateError if the certificate DNSName/IPAddress subject alternative name extension
           doesn't match the given hostname"""
        if not self.has_hostname(hostname):
            raise CertificateError("certificate doesn't match hostname")

    @method_args(one_of(X509_FMT_PEM, X509_FMT_DER))
    def export(self, format=X509_FMT_PEM):
        size = c_size_t(4096)
        pemdata = create_string_buffer(size.value)
        try:
            gnutls_x509_crt_export(self._c_object, format, cast(pemdata, c_void_p), byref(size))
        except MemoryError:
            pemdata = create_string_buffer(size.value)
            gnutls_x509_crt_export(self._c_object, format, cast(pemdata, c_void_p), byref(size))
        return pemdata.value


class X509PrivateKey(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_privkey_deinit
        instance._c_object = gnutls_x509_privkey_t()
        return instance

    @method_args(str, one_of(X509_FMT_PEM, X509_FMT_DER))
    def __init__(self, buf, format=X509_FMT_PEM):
        gnutls_x509_privkey_init(byref(self._c_object))
        data = gnutls_datum_t(cast(c_char_p(buf), POINTER(c_ubyte)), c_uint(len(buf)))
        gnutls_x509_privkey_import(self._c_object, byref(data), format)

    def __del__(self):
        self.__deinit(self._c_object)

    @method_args(one_of(X509_FMT_PEM, X509_FMT_DER))
    def export(self, format=X509_FMT_PEM):
        size = c_size_t(4096)
        pemdata = create_string_buffer(size.value)
        try:
            gnutls_x509_privkey_export(self._c_object, format, cast(pemdata, c_void_p), byref(size))
        except MemoryError:
            pemdata = create_string_buffer(size.value)
            gnutls_x509_privkey_export(self._c_object, format, cast(pemdata, c_void_p), byref(size))
        return pemdata.value



class X509Identity(object):
    """A X509 identity represents a X509 certificate and private key pair"""
    
    __slots__ = ('cert', 'key')
    
    @method_args(X509Certificate, X509PrivateKey)
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key
    
    def __setattr__(self, name, value):
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("can't set attribute")
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        if name in self.__slots__:
            raise AttributeError("can't delete attribute")
        object.__delattr__(self, name)


class X509CRL(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_crl_deinit
        instance._c_object = gnutls_x509_crl_t()
        return instance

    @method_args(str, one_of(X509_FMT_PEM, X509_FMT_DER))
    def __init__(self, buf, format=X509_FMT_PEM):
        gnutls_x509_crl_init(byref(self._c_object))
        data = gnutls_datum_t(cast(c_char_p(buf), POINTER(c_ubyte)), c_uint(len(buf)))
        gnutls_x509_crl_import(self._c_object, byref(data), format)

    def __del__(self):
        self.__deinit(self._c_object)

    @property
    def count(self):
        return gnutls_x509_crl_get_crt_count(self._c_object)

    @property
    def version(self):
        return gnutls_x509_crl_get_version(self._c_object)

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        try:
            gnutls_x509_crl_get_issuer_dn(self._c_object, dname, byref(size))
        except MemoryError:
            dname = create_string_buffer(size.value)
            gnutls_x509_crl_get_issuer_dn(self._c_object, dname, byref(size))
        return X509Name(dname.value)

    @method_args(X509Certificate)
    def is_revoked(self, cert):
        """Return True if certificate is revoked, False otherwise"""
        return bool(gnutls_x509_crt_check_revocation(cert._c_object, byref(self._c_object), 1))

    def check_revocation(self, cert, cert_name='certificate'):
        """Raise CertificateRevokedError if the given certificate is revoked"""
        if self.is_revoked(cert):
            raise CertificateRevokedError("%s was revoked" % cert_name)

    @method_args(one_of(X509_FMT_PEM, X509_FMT_DER))
    def export(self, format=X509_FMT_PEM):
        size = c_size_t(4096)
        pemdata = create_string_buffer(size.value)
        try:
            gnutls_x509_crl_export(self._c_object, format, cast(pemdata, c_void_p), byref(size))
        except MemoryError:
            pemdata = create_string_buffer(size.value)
            gnutls_x509_crl_export(self._c_object, format, cast(pemdata, c_void_p), byref(size))
        return pemdata.value



class DHParams(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_dh_params_deinit
        instance._c_object = gnutls_dh_params_t()
        return instance

    @method_args(int)
    def __init__(self, bits=1024):
        gnutls_dh_params_init(byref(self._c_object))
        gnutls_dh_params_generate2(self._c_object, bits)

    def __get__(self, obj, type_=None):
        return self._c_object

    def __set__(self, obj, value):
        raise AttributeError("Read-only attribute")

    def __del__(self):
        self.__deinit(self._c_object)


class CWrapper(object):
    ctype = None
    deinit = None

    def __init__(self, *args, **kwargs):
        super(CWrapper, self).__init__(*args, **kwargs)
        self._c_object = self.ctype()

    def __del__(self):
        if self.deinit:
            self.deinit(self._c_object)


class Cipher(CWrapper):
    ctype = gnutls_cipher_hd_t

    @method_args(int, str, str)
    def __init__(self, algo, key, iv):
        super(Cipher, self).__init__()
        dkey = gnutls_datum_t(cast(c_char_p(key), POINTER(c_ubyte)), c_uint(len(key)))
        div = gnutls_datum_t(cast(c_char_p(iv), POINTER(c_ubyte)), c_uint(len(iv)))
        gnutls_cipher_init(byref(self._c_object), algo, dkey, div)
        self.algorithm = algo
        self.deinit = gnutls_cipher_deinit

    @method_args(str)
    def set_iv(self, iv):
        gnutls_cipher_set_iv(self._c_object, c_char_p(iv), c_size_t(len(iv)))

    def add_auth(self, auth):
        gnutls_cipher_add_auth(self._c_object, c_char_p(auth), c_size_t(len(auth)))

    @method_args(str)
    def decrypt(self, cipher_text):
        pt = create_string_buffer(len(cipher_text))
        gnutls_cipher_decrypt2(self._c_object, c_char_p(cipher_text), c_size_t(cipher_text),
                               pt, c_size_t(len(pt)))
        return pt.value

    @method_args(str)
    def encrypt(self, plain_text):
        bs = gnutls_cipher_get_block_size(self.algorithm)
        ct = create_string_buffer(int(math.ceil(len(plain_text) / float(bs)) * bs))
        gnutls_cipher_encrypt2(self._c_object, c_char_p(plain_text), c_size_t(plain_text),
                               ct, c_size_t(len(ct)))
        return ct.value

    @method_args(int)
    def cipher_tag(self, tag_size):
        assert tag_size > 0
        tag = create_string_buffer(tag_size)
        gnutls_cipher_tag(self._c_object, tag, c_size_t(tag_size))
        return tag.value


class AEADCipher(CWrapper):
    ctype = gnutls_aead_cipher_hd_t

    @method_args(int, str)
    def __init__(self, algo, key):
        super(AEADCipher, self).__init__()
        data = gnutls_datum_t(cast(c_char_p(key), POINTER(c_ubyte)), c_uint(len(key)))
        gnutls_aead_cipher_init(byref(self._c_object), algo, byref(data))
        self.deinit = gnutls_aead_cipher_deinit

    @method_args(str, str, int, str)
    def encrypt(self, nonce, auth, tag_size, plain_text):
        csize = c_size_t(tag_size + len(plain_text) + 16)
        ct = create_string_buffer(csize.value)

        try:
            gnutls_aead_cipher_encrypt(
                self._c_object,
                c_char_p(nonce), c_size_t(len(nonce)),
                c_char_p(auth), c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(plain_text), c_size_t(len(plain_text)),
                cast(ct, c_void_p), byref(csize)
            )
        except MemoryError:
            ct = create_string_buffer(csize.value)
            gnutls_aead_cipher_encrypt(
                self._c_object,
                c_char_p(nonce), c_size_t(len(nonce)),
                c_char_p(auth), c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(plain_text), c_size_t(len(plain_text)),
                cast(ct, c_void_p), byref(csize)
            )

        return ct.value

    @method_args(str, str, int, str)
    def decrypt(self, nonce, auth, tag_size, cipher_text):
        psize = c_size_t(tag_size + len(cipher_text) + 16)
        pt = create_string_buffer(psize.value)

        try:
            gnutls_aead_cipher_decrypt(
                self._c_object,
                c_char_p(nonce), c_size_t(len(nonce)),
                c_char_p(auth), c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(cipher_text), c_size_t(len(cipher_text)),
                cast(pt, c_void_p), byref(psize)
            )
        except MemoryError:
            pt = create_string_buffer(psize.value)
            gnutls_aead_cipher_decrypt(
                self._c_object,
                c_char_p(nonce), c_size_t(len(nonce)),
                c_char_p(auth), c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(cipher_text), c_size_t(len(cipher_text)),
                cast(pt, c_void_p), byref(psize)
            )

        return pt.value
