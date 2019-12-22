/*
 * Call this module instead of time(0) or gettimeofday(&x, 0) who both freeze occasionally.
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

#ifndef	_STABLETIME_H_
#define	_STABLETIME_H_

#include <Arduino.h>
#include <sys/time.h>

class StableTime {
public:
  StableTime();
  ~StableTime();
  void loop(time_t);
  void loop(struct timeval *);
  time_t Query();
  void Query(struct timeval *);
  bool timeIsValid();

//private:
  struct timeval	now;
};

extern StableTime *stableTime;

#endif	/* _STABLETIME_H_ */
