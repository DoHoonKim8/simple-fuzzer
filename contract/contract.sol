// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract InvariantBreaker {
    bool public flag0 = true;
    bool public flag1 = true;

    function set0(uint8 val) public returns (bool) {
        if (val % 100 == 0) flag0 = false;
        return flag0;
    }

    function set1(uint8 val) public returns (bool) {
        if (val % 10 == 0 && !flag0) flag1 = false;
        return flag1;
    }
}

contract InvariantTest {
    InvariantBreaker public inv;

    function setUp() public {
        inv = new InvariantBreaker();
    }

    function invariant_neverFalse() public view returns (bool) {
        return inv.flag1();
    }
}
