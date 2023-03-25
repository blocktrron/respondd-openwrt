/* SPDX-FileCopyrightText: 2016-2019, Matthias Schiffer <mschiffer@universe-factory.net> */
/* SPDX-License-Identifier: BSD-2-Clause */

#include "respondd-statistics.h"

#include <respondd.h>


__attribute__ ((visibility ("default")))
const struct respondd_provider_info respondd_providers[] = {
	{"statistics", respondd_provider_statistics},
	{}
};
