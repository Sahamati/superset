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

import React, { useState, useEffect } from 'react';
import {
  SupersetClient,
  logging,
  supersetTheme,
  addAlpha,
} from '@superset-ui/core';
import { Layout, Typography, Form } from 'antd';
import { useToasts } from 'src/components/MessageToasts/withToasts';
import { Input } from '../../components/Input';
import Button from '../../components/Button';

interface MFAForm {
  code: string;
}

// Rewriting the resend button logic. Added a json api that calls and checks the ttl time. The resend button is going to remain active
// but it will return 429: too many requests error.
function ResendOtpButton() {
  const [cooldown, setCooldown] = useState(0);
  const { addDangerToast } = useToasts();
  // Fetch remaining TTL on mount
  const fetchTTL = async () => {
    try {
      const res = await SupersetClient.post({
        endpoint: '/mfa/resend?check_only=true',
        parseMethod: 'json',
      });
      if (res.json.ttl !== undefined) {
        setCooldown(res.json.ttl);
      }
    } catch (err) {
      console.error('Failed to fetch OTP TTL', err);
    }
  };

  const resendOtp = async () => {
    try {
      const res = await SupersetClient.post({
        endpoint: '/mfa/resend',
        parseMethod: 'json',
      });

      // Case 1: backend returns ttl -> just reset countdown
      if (res.json.ttl !== undefined) {
        setCooldown(res.json.ttl);
        return;
      }

      // Case 2: backend error with message
      if (res.json.error) {
        alert(res.json.message || 'Failed to resend OTP');
        return;
      }
    } catch (err) {
      console.error('Unexpected resend error', err);
      addDangerToast('Session expired or invalid. Please login again.');
    }
  };

  // Timer effect
  useEffect(() => {
    fetchTTL();
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const interval = setInterval(() => setCooldown(prev => prev - 1), 1000);
    return () => clearInterval(interval);
  }, [cooldown]);

  return (
    <Button onClick={resendOtp} disabled={cooldown > 0}>
      {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend OTP'}
    </Button>
  );
}

export default function MFA() {
  const [form] = Form.useForm<MFAForm>();
  const [loading, setLoading] = useState(false);

  const onFinish = (values: MFAForm) => {
    setLoading(true);
    SupersetClient.postForm('/mfa/verify', { code: values.code }, '_self')
      .catch(err => logging.error('MFA failed', err))
      .finally(() => {
        setLoading(false);
      });
  };

  return (
    <Layout
      style={{
        minHeight: '100vh',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
      <div
        style={{
          width: 400,
          padding: 24,
          borderRadius: 8,
          boxShadow: `0 2px 8px ${addAlpha(
            supersetTheme.colors.grayscale.dark2,
            0.1,
          )}`,
          background: `${supersetTheme.colors.grayscale.light5}`,
        }}
      >
        <Typography.Title
          level={4}
          style={{ textAlign: 'center', marginBottom: 16 }}
        >
          Enter OTP
        </Typography.Title>
        <Typography.Text style={{ marginBottom: 24, display: 'block' }}>
          Please enter the 6-digit OTP sent to your registered email.
        </Typography.Text>

        <Form layout="vertical" form={form} onFinish={onFinish}>
          <Form.Item<MFAForm>
            name="code"
            rules={[
              { required: true, message: 'Please enter your OTP' },
              { len: 6, message: 'OTP must be 6 digits' },
            ]}
            style={{ marginBottom: 24, minHeight: 56 }} // reserve space
          >
            <Input placeholder="Enter 6-digit OTP" maxLength={6} />
          </Form.Item>

          <Form.Item
            style={{
              width: '100%',
              textAlign: 'right',
            }}
          >
            <ResendOtpButton />
            <Button type="primary" htmlType="submit" loading={loading}>
              Verify
            </Button>
          </Form.Item>
        </Form>
      </div>
    </Layout>
  );
}
