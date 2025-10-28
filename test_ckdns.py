import pytest
from ckdns import ck_name, ck_whois

def test_ck_name():
    assert ck_name("prw.net") is True
    assert ck_name("www.prw.net") is False
    assert ck_name("end#i.com") is False
    assert ck_name("endi.") is False

def test_ck_whois():
    assert ck_whois("google.com") is True
#    assert ck_whois("example.invaliddomain") is False
    assert ck_whois("cloudium.org") is False
    
 #website-bucket-1db49f60 