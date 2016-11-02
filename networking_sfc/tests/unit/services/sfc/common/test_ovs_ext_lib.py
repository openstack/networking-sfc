# Copyright 2015 Futurewei. All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib import exceptions

from neutron.tests import base

from networking_sfc.services.sfc.common import ovs_ext_lib


class GetPortMaskTestCase(base.BaseTestCase):
    def setUp(self):
        super(GetPortMaskTestCase, self).setUp()

    def tearDown(self):
        super(GetPortMaskTestCase, self).tearDown()

    def test_single_port(self):
        masks = ovs_ext_lib.get_port_mask(100, 100)
        self.assertEqual(['0x64/0xffff'], masks)

    def test_invalid_min_port(self):
        self.assertRaises(
            exceptions.InvalidInput,
            ovs_ext_lib.get_port_mask,
            0, 100
        )

    def test_invalid_max_port(self):
        self.assertRaises(
            exceptions.InvalidInput,
            ovs_ext_lib.get_port_mask,
            100, 65536
        )

    def test_invalid_port_range(self):
        self.assertRaises(
            exceptions.InvalidInput,
            ovs_ext_lib.get_port_mask,
            100, 99
        )

    def test_one_port_mask(self):
        masks = ovs_ext_lib.get_port_mask(100, 101)
        self.assertEqual(['0x64/0xfffe'], masks)
        masks = ovs_ext_lib.get_port_mask(100, 103)
        self.assertEqual(['0x64/0xfffc'], masks)
        masks = ovs_ext_lib.get_port_mask(32768, 65535)
        self.assertEqual(['0x8000/0x8000'], masks)

    def test_multi_port_masks(self):
        masks = ovs_ext_lib.get_port_mask(101, 102)
        self.assertEqual(['0x65/0xffff', '0x66/0xffff'], masks)
        masks = ovs_ext_lib.get_port_mask(101, 104)
        self.assertEqual(
            ['0x65/0xffff', '0x66/0xfffe', '0x68/0xffff'],
            masks
        )
        masks = ovs_ext_lib.get_port_mask(1, 65535)
        self.assertEqual(
            [
                '0x1/0xffff',
                '0x2/0xfffe',
                '0x4/0xfffc',
                '0x8/0xfff8',
                '0x10/0xfff0',
                '0x20/0xffe0',
                '0x40/0xffc0',
                '0x80/0xff80',
                '0x100/0xff00',
                '0x200/0xfe00',
                '0x400/0xfc00',
                '0x800/0xf800',
                '0x1000/0xf000',
                '0x2000/0xe000',
                '0x4000/0xc000',
                '0x8000/0x8000'
            ],
            masks
        )
        masks = ovs_ext_lib.get_port_mask(32767, 65535)
        self.assertEqual(
            ['0x7fff/0xffff', '0x8000/0x8000'],
            masks
        )
