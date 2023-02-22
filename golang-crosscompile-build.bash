#!/bin/bash
# Orignal https://gist.github.com/jmervine/7d3f455e923cf2ac3c9e
# usage: ./golang-crosscompile-build.bash

#Get current working directory
currentdir=`pwd`

#Clear Sceeen
printf "\033c"

# Get Version out of target then replace . with _
versiond=$(go run *.go -version)
version=${versiond//./_}
#Remove White Space
version=${version// /}
versiond=${versiond// /}
platforms="windows/386 windows/amd64 linux/386 linux/amd64 linux/arm darwin/arm64"
printf " ---- Building LDAP User Import $versiond ---- \n"

rm -rf "release/"
mkdir release

printf "\n"
for platform in ${platforms}
do
    split=(${platform//\// })
    goos=${split[0]}
    os=${split[0]}
    goarch=${split[1]}
    arch=${split[1]}
    output=ldap_user_import
    package=ldap_user_import

    # add exe to windows output
    [[ "windows" == "$goos" ]] && output="$output.exe"
    [[ "386" == "$goarch" ]] && arch="x86"
    [[ "amd64" == "$goarch" ]] && arch="x64"

    printf "Platform: $goos - $goarch \n"

    destination="builds/$goos/$goarch/$output"

    printf "Go Build\n"
    GOOS=$goos GOARCH=$goarch go build -trimpath -o $destination -buildvcs=false
    # $target

    printf "Copy Source Files\n"
    #Copy Source to Build Dir
    cp LICENSE.md "builds/$goos/$goarch/LICENSE.md"
    cp README.md "builds/$goos/$goarch/README.md"

    printf "Build Zip \n"
    cd "builds/$goos/$goarch/"
    zip -r "${package}-${os}-${goarch}.zip" $output LICENSE.md README.md > /dev/null
    cp "${package}-${os}-${goarch}.zip" "../../../release/${package}-${os}-${goarch}.zip"
    cd $currentdir
    printf "\n"
done
printf "Clean Up \n"
rm -rf "builds/"
printf "Build Complete \n"
printf "\n"