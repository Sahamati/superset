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
import React, { useEffect, useState, useRef } from 'react';
import { SupersetClient, logging, supersetTheme } from '@superset-ui/core';
import { Layout, Typography, Button } from 'antd';
import Loading from 'src/components/Loading';
import { useToasts } from 'src/components/MessageToasts/withToasts';
import getBootstrapData from 'src/utils/getBootstrapData';

const theme = supersetTheme;
interface AgreementStatus {
  touAccepted: boolean;
  ppAccepted: boolean;
}

export default function AgreementsPage() {
  const [status, setStatus] = useState<AgreementStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [current, setCurrent] = useState<'tou' | 'pp' | null>(null);
  const [scrolledToEnd, setScrolledToEnd] = useState(false);
  const { addDangerToast } = useToasts();

  const scrollRef = useRef<HTMLDivElement | null>(null);

  // Fetch agreement status
  useEffect(() => {
    SupersetClient.get({ endpoint: '/agreements/api/status' })
      .then(res => {
        const s: AgreementStatus = res.json as AgreementStatus;
        setStatus(s);

        if (!s.touAccepted) setCurrent('tou');
        else if (!s.ppAccepted) setCurrent('pp');
        else setCurrent(null);
      })
      .catch(err => {
        logging.error('Failed to fetch agreement status', err);
        addDangerToast('Failed to load agreements');
      })
      .finally(() => setLoading(false));
  }, []);

  // Reset scroll tracking when agreement changes
  useEffect(() => {
    setScrolledToEnd(false);
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [current]);

  // Scroll handler
  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;

    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 5) {
      setScrolledToEnd(true);
    }
  };

  // Accept handler
  const handleAccept = (type: 'tou' | 'pp') => {
    const isFinal =
      (type === 'tou' && status?.ppAccepted) ||
      (type === 'pp' && status?.touAccepted);

    if (isFinal) {
      SupersetClient.postForm('/agreements/api/accept', { type }, '_self');
      return;
    }

    SupersetClient.post({
      endpoint: '/agreements/api/accept',
      jsonPayload: { type },
    })
      .then(res => {
        if (res.json) {
          setStatus(prev => {
            if (!prev) return prev;
            if (type === 'tou') {
              const updated = { ...prev, touAccepted: true };
              setCurrent('pp');
              return updated;
            }
            if (type === 'pp') {
              const updated = { ...prev, ppAccepted: true };
              setCurrent(null);
              return updated;
            }
            return prev;
          });
        }
      })
      .catch(err => {
        logging.error('Failed to accept agreement', err);
        addDangerToast('Failed to save agreement');
      });
  };

  if (loading) return <Loading />;
  const { tou_template, pp_template } = getBootstrapData().common;
  return (
    <Layout
      style={{ padding: theme.gridUnit * 12, maxWidth: 800, margin: '0 auto' }}
    >
      {current === 'tou' && (
        <div>
          <Typography.Title level={3}> SaaNs Terms of Use</Typography.Title>
          <div
            ref={scrollRef}
            onScroll={handleScroll}
            style={{
              maxHeight: 400,
              overflowY: 'auto',
              border: `1px solid ${theme.colors.grayscale.light2}`,
              padding: theme.gridUnit * 4,
              marginBottom: theme.gridUnit * 4,
            }}
          >
            <div dangerouslySetInnerHTML={{ __html: tou_template || '' }} />
          </div>
          <Button
            type="primary"
            disabled={!scrolledToEnd}
            onClick={() => handleAccept('tou')}
          >
            Accept Terms of Use
          </Button>
          {!scrolledToEnd && (
            <Typography.Text type="secondary" style={{ marginLeft: 8 }}>
              Please scroll to the bottom to enable
            </Typography.Text>
          )}
        </div>
      )}

      {current === 'pp' && (
        <div>
          <Typography.Title level={3}>Sahamati Privacy Policy</Typography.Title>
          <div
            ref={scrollRef}
            onScroll={handleScroll}
            style={{
              maxHeight: 400,
              overflowY: 'auto',
              border: `1px solid ${theme.colors.grayscale.light2}`,
              padding: theme.gridUnit * 4,
              marginBottom: theme.gridUnit * 4,
            }}
          >
            <div dangerouslySetInnerHTML={{ __html: pp_template || '' }} />
          </div>
          <Button
            type="primary"
            disabled={!scrolledToEnd}
            onClick={() => handleAccept('pp')}
          >
            Accept Privacy Policy
          </Button>
          {!scrolledToEnd && (
            <Typography.Text type="secondary" style={{ marginLeft: 8 }}>
              Please scroll to the bottom to enable
            </Typography.Text>
          )}
        </div>
      )}
    </Layout>
  );
}
