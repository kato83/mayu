import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { StatsTrendResponse } from '../models/stats-trend.model';
import { StatsTrendService } from './stats-trend.service';

describe('StatsTrendService', () => {
  let service: StatsTrendService;
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });

    service = TestBed.inject(StatsTrendService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should send GET request with no params when called with empty object', () => {
    const mockResponse: StatsTrendResponse = {
      range: '30d',
      group_by: 'day',
      data_points: [],
    };

    service.getTrend().subscribe((response) => {
      expect(response).toEqual(mockResponse);
    });

    const req = httpTesting.expectOne((r) => r.url === '/api/v1/stats/trend');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.keys()).toHaveLength(0);

    req.flush(mockResponse);
  });

  it('should send GET request with range param', () => {
    service.getTrend({ range: '90d' }).subscribe();

    const req = httpTesting.expectOne((r) => r.url === '/api/v1/stats/trend');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('range')).toBe('90d');
    expect(req.request.params.has('project_id')).toBe(false);
    expect(req.request.params.has('group_by')).toBe(false);
    expect(req.request.params.has('metric')).toBe(false);

    req.flush({ range: '90d', group_by: 'day', data_points: [] });
  });

  it('should send GET request with all params', () => {
    service
      .getTrend({
        range: '180d',
        project_id: 5,
        group_by: 'week',
        metric: 'severity',
      })
      .subscribe();

    const req = httpTesting.expectOne((r) => r.url === '/api/v1/stats/trend');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('range')).toBe('180d');
    expect(req.request.params.get('project_id')).toBe('5');
    expect(req.request.params.get('group_by')).toBe('week');
    expect(req.request.params.get('metric')).toBe('severity');

    req.flush({ range: '180d', group_by: 'week', data_points: [] });
  });

  it('should send GET request with project_id param', () => {
    service.getTrend({ project_id: 42 }).subscribe();

    const req = httpTesting.expectOne((r) => r.url === '/api/v1/stats/trend');
    expect(req.request.params.get('project_id')).toBe('42');
    expect(req.request.params.has('range')).toBe(false);

    req.flush({ range: '30d', group_by: 'day', data_points: [] });
  });

  it('should return data points in the response', () => {
    const mockResponse: StatsTrendResponse = {
      range: '30d',
      group_by: 'day',
      data_points: [
        { date: '2025-07-01', total: 25, critical: 2, high: 8, medium: 10, low: 5, new: 3, resolved: 1 },
        { date: '2025-07-02', total: 28, critical: 3, high: 9, medium: 11, low: 5, new: 4, resolved: 1 },
      ],
    };

    service.getTrend({ range: '30d', group_by: 'day' }).subscribe((response) => {
      expect(response.data_points).toHaveLength(2);
      expect(response.data_points[0].date).toBe('2025-07-01');
      expect(response.data_points[0].critical).toBe(2);
      expect(response.data_points[1].total).toBe(28);
    });

    const req = httpTesting.expectOne((r) => r.url === '/api/v1/stats/trend');
    req.flush(mockResponse);
  });

  it('should propagate HTTP errors', () => {
    service.getTrend({ range: 'invalid' }).subscribe({
      error: (error) => {
        expect(error.status).toBe(400);
      },
    });

    const req = httpTesting.expectOne((r) => r.url === '/api/v1/stats/trend');
    req.flush({ error: 'invalid range parameter' }, { status: 400, statusText: 'Bad Request' });
  });
});
