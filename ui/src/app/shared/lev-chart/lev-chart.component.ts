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

export interface LEVHistoryPoint {
  date: string;
  lev_score: number;
  epss_score: number;
  is_kev: boolean;
}

@Component({
  selector: 'app-lev-chart',
  standalone: true,
  template: `
    <div class="relative w-full" style="height: 200px">
      <canvas #chartCanvas></canvas>
    </div>
  `,
})
export class LevChartComponent implements AfterViewInit, OnChanges, OnDestroy {
  private readonly themeService = inject(ThemeService);

  @Input() history: LEVHistoryPoint[] = [];
  @ViewChild('chartCanvas') canvasRef!: ElementRef<HTMLCanvasElement>;

  private chart: Chart | null = null;
  private initialized = false;

  constructor() {
    effect(() => {
      this.themeService.mode();
      if (this.initialized) {
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

  private renderChart(): void {
    if (!this.canvasRef || this.history.length === 0) return;

    this.chart?.destroy();

    const isDark = document.documentElement.classList.contains('dark');
    const tickColor = isDark ? 'rgba(226, 232, 240, 0.8)' : 'rgba(100, 116, 139, 0.8)';
    const gridColor = isDark ? 'rgba(148, 163, 184, 0.15)' : 'rgba(148, 163, 184, 0.2)';

    const labels = this.history.map((p) => p.date);
    const levData = this.history.map((p) => p.lev_score * 100);

    const ctx = this.canvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'LEV (%)',
            data: levData,
            borderColor: 'rgb(234, 179, 8)',
            backgroundColor: 'rgba(234, 179, 8, 0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: levData.length > 60 ? 0 : 2,
            pointHoverRadius: 4,
            borderWidth: 2,
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
              label: (context) => `LEV: ${(context.parsed.y ?? 0).toFixed(2)}%`,
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
