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
 * IST Timezone utilities for date display
 * 
 * This module provides utilities for converting UTC datetime strings to Indian Standard Time (IST)
 * for display purposes in Superset filters. The conversion is display-only and does not affect
 * backend data processing, which continues to use UTC.
 * 
 * IST is UTC+5:30 (5 hours and 30 minutes ahead of UTC)
 */

/**
 * Converts a UTC datetime string to IST format for display
 * 
 * @param utcDateTime - The UTC datetime string to convert
 * @returns The IST datetime string in YYYY-MM-DDTHH:mm:ss format
 * 
 * @example
 * convertUTCToIST('2024-01-01T00:00:00') // Returns '2024-01-01T05:30:00'
 * convertUTCToIST('2024-01-01T12:00:00') // Returns '2024-01-01T17:30:00'
 */
export const convertUTCToIST = (utcDateTime: string): string => {
  if (!utcDateTime || utcDateTime === '-∞' || utcDateTime === '∞') {
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
    
    // Convert to IST (UTC+5:30)
    const istDate = new Date(utcDate.getTime() + (5.5 * 60 * 60 * 1000));
    
    // Format as readable IST date using UTC methods to avoid timezone conversion
    const year = istDate.getUTCFullYear();
    const month = String(istDate.getUTCMonth() + 1).padStart(2, '0');
    const day = String(istDate.getUTCDate()).padStart(2, '0');
    const hours = String(istDate.getUTCHours()).padStart(2, '0');
    const minutes = String(istDate.getUTCMinutes()).padStart(2, '0');
    const seconds = String(istDate.getUTCSeconds()).padStart(2, '0');
    
    const result = `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
    
    return result;
  } catch (error) {
    // If parsing fails, return original
    return utcDateTime;
  }
};

 