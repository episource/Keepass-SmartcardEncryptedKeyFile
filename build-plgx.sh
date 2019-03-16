#!/bin/bash

SCRIPTDIR="$(dirname $(readlink -e $0))"
KEEPASSEXE="$SCRIPTDIR/ThirdParty/KeePass/KeePass.exe"

mv "$SCRIPTDIR/SmartcardEncryptedKeyFile/Unblocker/episource.unblocker/episource.unblocker.csproj" "$SCRIPTDIR/SmartcardEncryptedKeyFile/Unblocker/episource.unblocker/episource.unblocker.csproj.bak"
$KEEPASSEXE --plgx-create "$(cygpath -w "$SCRIPTDIR/SmartcardEncryptedKeyFile")" --plgx-prereq-net:4.5 --plgx-prereq-kp:2.40
mv "$SCRIPTDIR/SmartcardEncryptedKeyFile/Unblocker/episource.unblocker/episource.unblocker.csproj.bak" "$SCRIPTDIR/SmartcardEncryptedKeyFile/Unblocker/episource.unblocker/episource.unblocker.csproj"

echo "Note: PLGX plugin is also created when building the solution. It is copied to the project's target directory."
read -rsn1 -p"Done with result: $? - Press any key to continue";echo