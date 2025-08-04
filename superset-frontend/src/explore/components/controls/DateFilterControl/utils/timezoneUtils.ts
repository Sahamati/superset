/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * Timezone utilities for date display
 * 
 * This module provides utilities for converting UTC datetime strings to different timezones
 * for display purposes in Superset filters. The conversion is display-only and does not affect
 * backend data processing, which continues to use UTC.
 */

export type TimezoneType = 'UTC' | 'IST';

/**
 * Converts a UTC datetime string to the specified timezone format for display
 * 
 * @param utcDateTime - The UTC datetime string to convert
 * @param timezone - The target timezone ('UTC' or 'IST')
 * @returns The datetime string in YYYY-MM-DDTHH:mm:ss format in the specified timezone
 * 
 * @example
 * convertUTCToTimezone('2024-01-01T00:00:00', 'UTC') // Returns '2024-01-01T00:00:00'
 * convertUTCToTimezone('2024-01-01T00:00:00', 'IST') // Returns '2024-01-01T05:30:00'
 */
export const convertUTCToTimezone = (utcDateTime: string, timezone: TimezoneType = 'UTC'): string => {
  if (!utcDateTime || utcDateTime === '-∞' || utcDateTime === '∞') {
    return utcDateTime;
  }

  // If timezone is UTC, return as is
  if (timezone === 'UTC') {
    return utcDateTime;
  }

  try {
    // Handle different date formats
    let utcDate: Date;
    
    // If it already has timezone info, parse as is
    if (utcDateTime.includes('Z') || utcDateTime.includes('+')) {
      utcDate = new Date(utcDateTime);
    } else if (utcDateTime.includes('T')) {
      // Assume it's UTC if no timezone indicator
      utcDate = new Date(utcDateTime + 'Z');
    } else {
      // Try parsing as is
      utcDate = new Date(utcDateTime);
    }
    
    let targetDate: Date;
    
    if (timezone === 'IST') {
      // Convert to IST (UTC+5:30)
      targetDate = new Date(utcDate.getTime() + (5.5 * 60 * 60 * 1000));
    } else {
      // Default to UTC
      targetDate = utcDate;
    }
    
    // Format as readable date using UTC methods to avoid timezone conversion
    const year = targetDate.getUTCFullYear();
    const month = String(targetDate.getUTCMonth() + 1).padStart(2, '0');
    const day = String(targetDate.getUTCDate()).padStart(2, '0');
    const hours = String(targetDate.getUTCHours()).padStart(2, '0');
    const minutes = String(targetDate.getUTCMinutes()).padStart(2, '0');
    const seconds = String(targetDate.getUTCSeconds()).padStart(2, '0');
    
    const result = `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
    
    return result;
  } catch (error) {
    // If parsing fails, return original
    return utcDateTime;
  }
};

 