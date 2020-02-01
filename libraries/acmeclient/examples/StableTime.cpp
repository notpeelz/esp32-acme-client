/*
 * Call this module instead of time(0) or gettimeofday(&x, 0) who both freeze occasionally.
 * Currently (with a quick loop()) there's no need to make this complicated.
 *
 * In another case, this could be implemented as one process that periodically does a call
 * to gettimeofday(), and another to monitor whether it freezes.
 *
 * Copyright (c) 2019 Danny Backx
 *
 * License (GNU Lesser General Public License) :
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 3 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "StableTime.h"

StableTime *stableTime;

StableTime::StableTime() {
}

StableTime::~StableTime() {
}

void StableTime::loop(struct timeval *ptv) {
  now = *ptv;
}

void StableTime::loop(time_t n) {
  now.tv_sec = n;
  now.tv_usec = 0;
}

time_t StableTime::Query() {
  return now.tv_sec;
}

void StableTime::Query(struct timeval *ptv) {
  *ptv = now;
}

bool StableTime::timeIsValid() {
  if (now.tv_sec < 1000)
    return false;
  return true;
}
