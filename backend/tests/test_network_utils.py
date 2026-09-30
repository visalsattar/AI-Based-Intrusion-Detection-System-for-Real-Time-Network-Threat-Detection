import network_utils


def test_multicast_and_broadcast_macs_are_not_unicast():
    assert not network_utils._is_unicast_mac("01:00:5e:00:00:01")
    assert not network_utils._is_unicast_mac("ff:ff:ff:ff:ff:ff")
    assert not network_utils._is_unicast_mac("00:00:00:00:00:00")


def test_valid_unicast_macs_are_accepted():
    assert network_utils._is_unicast_mac("02:11:22:33:44:55")
    assert network_utils._is_unicast_mac("02-11-22-33-44-55")
