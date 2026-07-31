import {
  type AfterViewInit,
  Component,
  type ElementRef,
  input,
  type OnChanges,
  type OnDestroy,
  ViewChild,
} from '@angular/core';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

@Component({
  selector: 'app-score-breakdown-chart',
  standalone: true,
  template: `
    <div class="relative w-full" [style.height]="height()">
      <canvas #chartCanvas></canvas>
    </div>
  `,
})
export class ScoreBreakdownChartComponent implements AfterViewInit, OnChanges, OnDestroy {
  readonly signals =
    input.required<{ signal: string; contribution: number; effective_weight: number; available: boolean }[]>();
  readonly chartType = input<'bar' | 'radar'>('bar');
  readonly height = input<string>('220px');

  @ViewChild('chartCanvas') canvasRef!: ElementRef<HTMLCanvasElement>;

  private chart: Chart | null = null;

  ngAfterViewInit(): void {
    this.renderChart();
  }

  ngOnChanges(): void {
    if (this.chart) {
      this.renderChart();
    }
  }

  ngOnDestroy(): void {
    if (this.chart) {
      this.chart.destroy();
    }
  }

  private get isDark(): boolean {
    return document.documentElement.classList.contains('dark');
  }

  private get tickColor(): string {
    return this.isDark ? 'rgba(226, 232, 240, 0.8)' : 'rgba(100, 116, 139, 0.8)';
  }

  private get gridColor(): string {
    return this.isDark ? 'rgba(148, 163, 184, 0.15)' : 'rgba(148, 163, 184, 0.2)';
  }

  private renderChart(): void {
    if (!this.canvasRef) return;

    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }

    const ctx = this.canvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    const data = this.signals();
    const labels = data.map((s) => s.signal);
    const contributions = data.map((s) => s.contribution);
    const weights = data.map((s) => s.effective_weight);

    const colors = [
      'rgba(239, 68, 68, 0.7)', // red
      'rgba(249, 115, 22, 0.7)', // orange
      'rgba(234, 179, 8, 0.7)', // yellow
      'rgba(34, 197, 94, 0.7)', // green
      'rgba(59, 130, 246, 0.7)', // blue
      'rgba(139, 92, 246, 0.7)', // violet
      'rgba(236, 72, 153, 0.7)', // pink
      'rgba(20, 184, 166, 0.7)', // teal
    ];

    if (this.chartType() === 'radar') {
      this.chart = new Chart(ctx, {
        type: 'radar',
        data: {
          labels,
          datasets: [
            {
              label: 'Contribution',
              data: contributions,
              backgroundColor: 'rgba(99, 102, 241, 0.2)',
              borderColor: '#6366f1',
              borderWidth: 2,
              pointBackgroundColor: '#6366f1',
            },
            {
              label: 'Weight',
              data: weights,
              backgroundColor: 'rgba(234, 179, 8, 0.1)',
              borderColor: '#eab308',
              borderWidth: 1,
              pointBackgroundColor: '#eab308',
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { labels: { color: this.tickColor, font: { size: 10 } } },
          },
          scales: {
            r: {
              ticks: { color: this.tickColor, font: { size: 9 } },
              grid: { color: this.gridColor },
              pointLabels: { color: this.tickColor, font: { size: 10 } },
            },
          },
        },
      });
    } else {
      this.chart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [
            {
              label: 'Contribution',
              data: contributions,
              backgroundColor: colors.slice(0, labels.length),
              borderWidth: 0,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: { display: false },
          },
          scales: {
            x: {
              beginAtZero: true,
              max: 1,
              ticks: { font: { size: 10 }, color: this.tickColor },
              grid: { color: this.gridColor },
            },
            y: {
              ticks: { font: { size: 10 }, color: this.tickColor },
              grid: { display: false },
            },
          },
        },
      });
    }
  }
}
