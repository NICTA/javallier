import subprocess
import base64
import cmath


def base64url_decode(payload):
    l = len(payload) % 4
    if l == 2:
        payload += '=='
    elif l == 3:
        payload += '='
    elif l != 0:
        raise ValueError('Invalid base64 string')
    return base64.urlsafe_b64decode(payload.encode('utf-8'))


def run_jar_command(cmd):

    command = ['java', '-jar', './target/scala-2.10/javallier.jar'] + list(cmd)

    proc = subprocess.Popen(command,
                            universal_newlines=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()

    if 'Exception' in err or 'Parsing failed' in err:
        raise RuntimeError("javallier.jar raises an exception: " + err)

    return out, err


def check_help_command_output(out, command):
    assert 'usage:' in out
    assert command in out
    assert 'Options:' in out


def check_help_output(out):
    check_help_command_output(out, 'Commands:')


def check_genpkey_output(out):
    assert 'pub' in out
    assert 'kty' in out
    assert 'lambda' in out
    assert 'mu' in out


def check_genpkey_message_output(out, msg):
    check_genpkey_output(out)
    assert msg in out


def check_genpkey_verbose_output(out, err):
    # 'genpkey' output is redirected to stdout
    check_genpkey_output(out)
    # But 'verbose' output is redirected to stderr
    assert 'INFO' in err


def get_keylength(priv_key):
    mod = priv_key['pub']['n']
    return int.from_bytes(base64url_decode(mod), 'big').bit_length()


def check_extracted_public_key(pub_key_json):
    assert 'n' in pub_key_json
    assert 'kty' in pub_key_json
    assert 'alg' in pub_key_json
    assert 'lambda' not in pub_key_json
    assert 'mu' not in pub_key_json
    assert '=' not in pub_key_json['n']
    assert '/' not in pub_key_json['n']
    assert '+' not in pub_key_json['n']


def check_encrypted_number(out):
    assert 'e' in out
    assert 'v' in out


def check_decrypted_number(out):
    assert 'e' in out
    assert 'v' in out


def isclose(a,
            b,
            rel_tol=1e-9,
            abs_tol=0.0,
            method='weak'):
    """
    returns True if a is close in value to b. False otherwise
    :param a: one of the values to be tested
    :param b: the other value to be tested
    :param rel_tol=1e-8: The relative tolerance -- the amount of error
                         allowed, relative to the magnitude of the input
                         values.
    :param abs_tol=0.0: The minimum absolute tolerance level -- useful for
                        comparisons to zero.
    :param method: The method to use. options are:
                  "asymmetric" : the b value is used for scaling the tolerance
                  "strong" : The tolerance is scaled by the smaller of
                             the two values
                  "weak" : The tolerance is scaled by the larger of
                           the two values
                  "average" : The tolerance is scaled by the average of
                              the two values.
    NOTES:
    -inf, inf and NaN behave similar to the IEEE 754 standard. That
    -is, NaN is not close to anything, even itself. inf and -inf are
    -only close to themselves.
    Complex values are compared based on their absolute value.
    The function can be used with Decimal types, if the tolerance(s) are
    specified as Decimals::
      isclose(a, b, rel_tol=Decimal('1e-9'))
    See PEP-0485 for a detailed description - https://www.python.org/dev/peps/pep-0485/
    """
    if method not in ("asymmetric", "strong", "weak", "average"):
        raise ValueError('method must be one of: "asymmetric",'
                         ' "strong", "weak", "average"')

    if rel_tol < 0.0 or abs_tol < 0.0:
        raise ValueError('error tolerances must be non-negative')

    if a == b:  # short-circuit exact equality
        return True
    # use cmath so it will work with complex or float
    if cmath.isinf(a) or cmath.isinf(b):
        # This includes the case of two infinities of opposite sign, or
        # one infinity and one finite number. Two infinities of opposite sign
        # would otherwise have an infinite relative tolerance.
        return False
    diff = abs(b - a)
    if method == "asymmetric":
        return (diff <= abs(rel_tol * b)) or (diff <= abs_tol)
    elif method == "strong":
        return (((diff <= abs(rel_tol * b)) and
                 (diff <= abs(rel_tol * a))) or
                (diff <= abs_tol))
    elif method == "weak":
        return (((diff <= abs(rel_tol * b)) or
                 (diff <= abs(rel_tol * a))) or
                (diff <= abs_tol))
    elif method == "average":
        return ((diff <= abs(rel_tol * (a + b) / 2) or
                 (diff <= abs_tol)))
    else:
        raise ValueError('method must be one of:'
                         ' "asymmetric", "strong", "weak", "average"')