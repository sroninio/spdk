#!/bin/bash -ex
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

branch=$(git name-rev --name-only HEAD | awk -F/ '{print $NF}')

if [ -z "$VER" ]; then
	export VER=$(echo $branch | grep -o '[0-9]\+\(\.[0-9]\+\)*')
fi

REV=${BUILD_NUMBER:-1}

git_tag="v$VER-${REV}"

git tag $git_tag
git push origin $git_tag
