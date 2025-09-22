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

import React, { useState } from 'react';
import { SupersetClient, logging } from '@superset-ui/core';

import { Input } from '../../components/Input';
import Button from '../../components/Button';
import { Layout, Typography } from 'antd';
import { Form } from 'antd';


interface MFAForm {
  code: string;
}

// const bootstrapData = getBootstrapData();
function ResendOtpButton() {
  const [cooldown, setCooldown] = useState(30);

  const resendOtp = async () => {
    try {
      await SupersetClient.post({
        endpoint: '/mfa/resend',
        parseMethod: 'text', // avoids JSON parse error
      });
      setCooldown(30);
    } catch (err) {
      alert('Failed to resend OTP');
      console.error(err);
    }
  };

  // cooldown timer
  React.useEffect(() => {
  if (cooldown <= 0) return;

  const interval = setInterval(() => setCooldown(prev => prev - 1), 1000);

  return () => clearInterval(interval);
}, [cooldown]);


  return (
    <Button onClick={resendOtp} disabled={cooldown > 0}>
      {cooldown > 0 ? `Resend in ${cooldown}s` : "Resend OTP"}
    </Button>
  );
}

export default function MFA() {
  const [form] = Form.useForm<MFAForm>();
  const [loading, setLoading] = useState(false);
  // const [disabled, setDisabled] = useState(true);
  // const [countdown, setCountdown] = useState(30);

  const onFinish = (values: MFAForm) => {
    setLoading(true);
    SupersetClient.postForm('/mfa/verify', { code: values.code }, '_self')
      .catch(err => logging.error("MFA failed", err))
      .finally(() => {
        setLoading(false);
      });
    // setCountdown(30);
    // if (countdown > 30) {
    //   setDisabled(false);
    // }
  };

  // const handleResend = () => {
  //   logging.info("Resend OTP clicked");
  //   setDisabled(true);
  //   SupersetClient.postForm('/mfa/resend', {}, '_self')
  //     .then(() => {
  //       logging.info("OTP resent successfully");
  //     })
  //     .catch(err => {
  //       logging.error("Failed to resend OTP", err);
  //     });
  // }

  return (
    <Layout style={{ minHeight: "100vh", display: "flex", justifyContent: "center", alignItems: "center" }}>
      <div style={{ width: 400, padding: 24, borderRadius: 8, boxShadow: "0 2px 8px rgba(0,0,0,0.1)", background: "#fff" }}>

        <Typography.Title level={4} style={{ textAlign: "center", marginBottom: 16 }}>
          Enter OTP
        </Typography.Title>
        <Typography.Text style={{ marginBottom: 24, display: "block" }}>
          Please enter the 6-digit OTP sent to your registered email.
        </Typography.Text>

        <Form layout="vertical" form={form} onFinish={onFinish}>
          <Form.Item<MFAForm>
            name="code"
            rules={[{ required: true, message: "Please enter your OTP" }, { len: 6, message: "OTP must be 6 digits" }]}
            style={{ marginBottom: 24, minHeight: 56 }} // reserve space
          >
            <Input placeholder="Enter 6-digit OTP" maxLength={6} />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} >
              Verify
            </Button>
            {/* <Button type="default" onClick={handleResend} disabled={disabled} >
              Resend OTP
            </Button> */}
            <ResendOtpButton />
          </Form.Item>
        </Form>
      </div>
    </Layout>

  );
}
