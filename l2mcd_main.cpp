/*
 * Copyright 2019 Broadcom.  The term “Broadcom” refers to Broadcom Inc. and/or
 * its subsidiaries.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <unistd.h>

extern "C" void l2mcd_main(int flag);

int main(int argc, char **argv)
{
    int aflag=0;
    int opt;
    while ((opt = getopt(argc, argv, "n:")) != -1) 
    {
        switch (opt) 
        {
        case 'n':
           aflag=atoi(optarg);
           break;
        default:
           break;
        }
    }
    l2mcd_main(aflag);
    return 0;
}
