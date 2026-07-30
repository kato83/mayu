import {
  type AfterViewInit,
  Component,
  type ElementRef,
  effect,
  Input,
  inject,
  type OnChanges,
  type OnDestroy,
  type SimpleChanges,
  ViewChild,
} from '@angular/core';
import { Chart, registerables } from 'chart.js';

import { ThemeService } from '../../services/theme.service';

Chart.register(...registerables);

export interface EPSSHistoryPoint {
  date: string;
  epss: number;
  percentile: number;
}

@Component({
  selector: 'app-epss-chart',
  standalone: true,
  template: `
    <div class="relative w-full" style="height: 200px">
      <canvas #chartCanvas></canvas>
    </div>
  `,
})
export class EpssChartComponent implements AfterViewInit, OnChanges, OnDestroy {
  private readonly themeService = inject(ThemeService);

  @Input() history: EPSSHistoryPoint[] = [];
  @ViewChild('chartCanvas') canvasRef!: ElementRef<HTMLCanvasElement>;

  private chart: Chart | null = null;
  private initialized = false;

  constructor() {
    effect(() => {
      // Track theme mode signal to trigger re-render on theme change
      this.themeService.mode();
      if (this.initialized) {
        // Small delay to let the DOM class toggle apply
        setTimeout(() => this.renderChart(), 50);
      }
    });
  }

  ngAfterViewInit(): void {
    this.initialized = true;
    this.renderChart();
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['history'] && this.canvasRef) {
      this.renderChart();
    }
  }

  ngOnDestroy(): void {
    this.chart?.destroy();
  }

  /**
   * Fill gaps in the history data with null values so Chart.js renders
   * a visual break for periods where no EPSS data was ingested.
   * A gap is detected when the interval between consecutive data points
   * exceeds twice the median interval.
   */
  private fillGaps(history: EPSSHistoryPoint[]): { labels: string[]; data: (number | null)[] } {
    if (history.length < 2) {
      return {
        labels: history.map((p) => p.date),
        data: history.map((p) => p.epss * 100),
      };
    }

    // Calculate intervals between consecutive points (in days)
    const timestamps = history.map((p) => new Date(p.date).getTime());
    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }

    // Use median interval as the "normal" step
    const sorted = [...intervals].sort((a, b) => a - b);
    const medianInterval = sorted[Math.floor(sorted.length / 2)];
    // Gap threshold: more than 2x the median interval
    const gapThreshold = medianInterval * 2;

    const labels: string[] = [history[0].date];
    const data: (number | null)[] = [history[0].epss * 100];

    for (let i = 1; i < history.length; i++) {
      const interval = timestamps[i] - timestamps[i - 1];
      if (interval > gapThreshold) {
        // Insert a null point at 1 day after the last valid point to break the line
        const gapStart = new Date(timestamps[i - 1] + medianInterval);
        labels.push(gapStart.toISOString().slice(0, 10));
        data.push(null);
      }
      labels.push(history[i].date);
      data.push(history[i].epss * 100);
    }

    return { labels, data };
  }

  private renderChart(): void {
    if (!this.canvasRef || this.history.length === 0) return;

    this.chart?.destroy();

    const isDark = document.documentElement.classList.contains('dark');
    const tickColor = isDark ? 'rgba(226, 232, 240, 0.8)' : 'rgba(100, 116, 139, 0.8)';
    const gridColor = isDark ? 'rgba(148, 163, 184, 0.15)' : 'rgba(148, 163, 184, 0.2)';

    const { labels, data: epssData } = this.fillGaps(this.history);

    const ctx = this.canvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'EPSS (%)',
            data: epssData,
            borderColor: 'rgb(99, 102, 241)',
            backgroundColor: 'rgba(99, 102, 241, 0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: epssData.length > 60 ? 0 : 2,
            pointHoverRadius: 4,
            borderWidth: 2,
            spanGaps: false,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: 'index',
        },
        plugins: {
          legend: {
            display: false,
          },
          tooltip: {
            callbacks: {
              label: (context) => `EPSS: ${(context.parsed.y ?? 0).toFixed(2)}%`,
            },
          },
        },
        scales: {
          x: {
            ticks: {
              maxTicksLimit: 8,
              font: { size: 10 },
              color: tickColor,
            },
            grid: {
              display: false,
            },
          },
          y: {
            min: 0,
            max: 100,
            ticks: {
              callback: (value) => `${value}%`,
              font: { size: 10 },
              color: tickColor,
            },
            grid: {
              color: gridColor,
            },
          },
        },
      },
    });
  }
}
