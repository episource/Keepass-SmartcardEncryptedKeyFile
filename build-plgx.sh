#!/bin/bash

SCRIPTDIR="$(dirname $(readlink -e $0))"
KEEPASSEXE="$SCRIPTDIR/ThirdParty/KeePass/KeePass.exe"
$KEEPASSEXE --plgx-create "$(cygpath -w "$SCRIPTDIR/SmartcardEncryptedKeyFile")" --plgx-prereq-net:4.5 --plgx-prereq-kp:2.40
read -rsn1 -p"Done with result: $? - Press any key to continue";echo