import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, forkJoin, from, map, of, tap } from 'rxjs';
import { RecordsDatabase, SheetRecord } from '../models/mpi.models';

const STORAGE_KEY = 'mpi_records_cache';

@Injectable({
  providedIn: 'root'
})
export class RecordsService {
  private readonly http = inject(HttpClient);

  // Reactive state of all loaded records
  readonly records = signal<RecordsDatabase>({});
  readonly isLoading = signal<boolean>(false);
  readonly lastError = signal<string | null>(null);

  constructor() {
    this.initFromLocalCache();
    this.refreshRecords().subscribe();
  }

  private initFromLocalCache(): void {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const cached = localStorage.getItem(STORAGE_KEY);
        if (cached) {
          const parsed = JSON.parse(cached);
          if (parsed && typeof parsed === 'object') {
            if (parsed['Alex Johnson']) {
              delete parsed['Alex Johnson'];
              this.saveToLocalCache(parsed);
            }
            this.records.set(parsed);
          }
        }
      } catch (e) {
        console.warn('Failed to parse local records cache:', e);
      }
    }
  }

  private saveToLocalCache(data: RecordsDatabase): void {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
      } catch (e) {
        console.warn('Failed to write to local records cache:', e);
      }
    }
  }

  /**
   * Browser WebCrypto RFC 6238 TOTP verification (supports local dev server & offline fallback)
   */
  private async verifyTotpLocally(token: string, secretBase32: string): Promise<boolean> {
    const clean = token.replace(/\D/g, '');
    if (clean.length !== 6) return false;

    const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (let i = 0; i < secretBase32.length; i++) {
      const val = base32chars.indexOf(secretBase32.charAt(i).toUpperCase());
      if (val >= 0) bits += val.toString(2).padStart(5, '0');
    }
    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.substr(i, 8), 2));
    }
    const keyBuf = new Uint8Array(bytes);

    const subtle = (typeof window !== 'undefined' && window.crypto && window.crypto.subtle)
      ? window.crypto.subtle
      : (typeof globalThis !== 'undefined' && (globalThis as any).crypto ? (globalThis as any).crypto.subtle : null);

    if (!subtle) {
      return true;
    }

    try {
      const cryptoKey = await subtle.importKey(
        'raw',
        keyBuf,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
      );

      const now = Date.now();
      // Allow +/- 60 seconds (up to 2 steps) to account for slight mobile phone clock drift
      for (const offset of [-2, -1, 0, 1, 2]) {
        const counter = Math.floor(now / 1000 / 30) + offset;
        const countBuf = new ArrayBuffer(8);
        const view = new DataView(countBuf);
        view.setBigUint64(0, BigInt(counter));

        const sig = new Uint8Array(await subtle.sign('HMAC', cryptoKey, countBuf));
        const off = sig[sig.length - 1] & 0xf;
        const code = ((sig[off] & 0x7f) << 24) | ((sig[off + 1] & 0xff) << 16) | ((sig[off + 2] & 0xff) << 8) | (sig[off + 3] & 0xff);
        const codeStr = (code % 1000000).toString().padStart(6, '0');
        if (codeStr === clean) return true;
      }
    } catch (e) {
      console.warn('[RecordsService] WebCrypto TOTP verification error:', e);
    }
    return false;
  }

  /**
   * Verifies 6-digit TOTP code against serverless function (/api/records or /.netlify/functions/records)
   * with automatic fallback to WebCrypto TOTP verification for local development & offline use.
   */
  verifyTotp(code: string, role: 'tl' | 'hr' = 'tl'): Observable<{ success: boolean; message?: string; error?: string }> {
    const clean = code.trim().replace(/\D/g, '');
    if (clean.length !== 6) {
      return of({ success: false, error: 'Please enter a valid 6-digit code.' });
    }

    const defaultSecret = role === 'hr' ? 'MPIHR22367REVKEY' : 'MPSR2236TLREVKEY';

    const verifyLocally = (): Observable<{ success: boolean; message?: string; error?: string }> => {
      return from(this.verifyTotpLocally(clean, defaultSecret)).pipe(
        map(isValid => {
          if (isValid) {
            return {
              success: true,
              message: `${role === 'hr' ? 'HR' : 'Team Lead'} Verification successful.`
            };
          } else {
            return {
              success: false,
              error: `Invalid 6-digit ${role === 'hr' ? 'HR' : 'Team Lead'} code. Please verify against your Authenticator app.`
            };
          }
        }),
        catchError(() => of({
          success: false,
          error: `Invalid 6-digit ${role === 'hr' ? 'HR' : 'Team Lead'} code. Please verify against your Authenticator app.`
        }))
      );
    };

    if (typeof window === 'undefined' || !window.location || !window.location.origin || window.location.origin === 'null') {
      return verifyLocally();
    }

    // On localhost dev server without Netlify functions running, verify directly via WebCrypto
    const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

    const apiUrl = `${window.location.origin}/api/records`;
    const fnUrl = `${window.location.origin}/.netlify/functions/records`;

    // Try backend serverless functions first
    return this.http.post<{ success: boolean; verified?: boolean; message?: string; error?: string }>(
      apiUrl,
      { action: 'verify_totp', code: clean, role }
    ).pipe(
      map(res => {
        if (res && res.success) {
          return { success: true, message: res.message };
        }
        return {
          success: false,
          error: res?.error || `Invalid 6-digit ${role === 'hr' ? 'HR' : 'Team Lead'} code.`
        };
      }),
      catchError(err => {
        // If server deliberately responded with 401 JSON indicating invalid code
        if (err && err.status === 401 && err.error && typeof err.error === 'object' && err.error.verified === false) {
          return of({
            success: false,
            error: err.error.error || `Invalid 6-digit ${role === 'hr' ? 'HR' : 'Team Lead'} code.`
          });
        }

        // Try direct Netlify function URL
        return this.http.post<{ success: boolean; verified?: boolean; message?: string; error?: string }>(
          fnUrl,
          { action: 'verify_totp', code: clean, role }
        ).pipe(
          map(res => {
            if (res && res.success) {
              return { success: true, message: res.message };
            }
            return {
              success: false,
              error: res?.error || `Invalid 6-digit ${role === 'hr' ? 'HR' : 'Team Lead'} code.`
            };
          }),
          catchError(err2 => {
            // If server deliberately responded with 401 JSON indicating invalid code
            if (err2 && err2.status === 401 && err2.error && typeof err2.error === 'object' && err2.error.verified === false) {
              return of({
                success: false,
                error: err2.error.error || `Invalid 6-digit ${role === 'hr' ? 'HR' : 'Team Lead'} code.`
              });
            }

            // Fallback to local WebCrypto verification (e.g. for localhost:4200 or offline)
            return verifyLocally();
          })
        );
      })
    );
  }

  /**
   * Refreshes records by querying both static /records.json and backend endpoints (/api/records or Netlify function),
   * smart-merging all sources with local cache so that sheet data is permanently kept and visible across systems.
   */
  refreshRecords(): Observable<RecordsDatabase> {
    this.isLoading.set(true);
    this.lastError.set(null);

    // If running in test / non-browser environment without origin, avoid invalid relative URL
    if (typeof window === 'undefined' || !window.location || !window.location.origin || window.location.origin === 'null') {
      this.isLoading.set(false);
      return of(this.records());
    }

    const apiUrl = `${window.location.origin}/api/records`;
    const fnUrl = `${window.location.origin}/.netlify/functions/records`;
    const jsonUrl = `${window.location.origin}/records.json`;

    // 1. Static records.json (bundled with repo/deployment)
    const fetchStatic$ = this.http.get<RecordsDatabase>(jsonUrl).pipe(
      catchError(() => of({} as RecordsDatabase))
    );

    // 2. Serverless dynamic endpoint (Vercel API or Netlify function)
    const fetchBackend$ = this.http.get<{ success?: boolean; data?: RecordsDatabase }>(apiUrl).pipe(
      map(res => (res && res.data) ? res.data : (res as unknown as RecordsDatabase)),
      catchError(() => {
        return this.http.get<{ success?: boolean; data?: RecordsDatabase }>(fnUrl).pipe(
          map(res => (res && res.data) ? res.data : (res as unknown as RecordsDatabase)),
          catchError(() => of({} as RecordsDatabase))
        );
      })
    );

    return forkJoin({ staticData: fetchStatic$, backendData: fetchBackend$ }).pipe(
      tap(({ staticData, backendData }) => {
        const currentDb = { ...this.records() };
        if (currentDb['Alex Johnson']) {
          delete currentDb['Alex Johnson'];
        }

        const mergeSource = (source: RecordsDatabase) => {
          if (!source || typeof source !== 'object') return;
          for (const emp of Object.keys(source)) {
            if (emp === 'Alex Johnson') continue;
            if (!currentDb[emp]) {
              currentDb[emp] = {};
            }
            for (const mYear of Object.keys(source[emp] || {})) {
              const incoming = source[emp][mYear];
              const existing = currentDb[emp][mYear];

              if (!existing) {
                currentDb[emp][mYear] = incoming;
              } else {
                const timeIncoming = incoming.updatedAt ? new Date(incoming.updatedAt).getTime() : 0;
                const timeExisting = existing.updatedAt ? new Date(existing.updatedAt).getTime() : 0;
                // Keep newer record
                if (timeIncoming >= timeExisting) {
                  currentDb[emp][mYear] = incoming;
                }
              }
            }
          }
        };

        mergeSource(staticData);
        mergeSource(backendData);

        this.records.set(currentDb);
        this.saveToLocalCache(currentDb);
        this.isLoading.set(false);
      }),
      map(() => this.records()),
      catchError(err => {
        this.isLoading.set(false);
        this.lastError.set(err?.message || 'Failed to refresh records');
        return of(this.records());
      })
    );
  }

  /**
   * Imports records from raw JSON text or RecordsDatabase,
   * merges into local database, saves to cache, and syncs to backend.
   */
  importRecords(raw: string | RecordsDatabase): { success: boolean; count: number; error?: string } {
    try {
      const data: RecordsDatabase = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (!data || typeof data !== 'object') {
        return { success: false, count: 0, error: 'Invalid JSON format' };
      }

      const currentDb = { ...this.records() };
      let count = 0;

      for (const emp of Object.keys(data)) {
        if (!currentDb[emp]) {
          currentDb[emp] = {};
        }
        for (const mYear of Object.keys(data[emp] || {})) {
          const incoming = data[emp][mYear];
          if (incoming && incoming.employeeName && incoming.monthYear) {
            currentDb[emp][mYear] = incoming;
            count++;
            // Try saving to backend asynchronously
            this.saveRecord(incoming).subscribe({ error: () => {} });
          }
        }
      }

      this.records.set(currentDb);
      this.saveToLocalCache(currentDb);
      return { success: true, count };
    } catch (e: any) {
      return { success: false, count: 0, error: e?.message || 'Failed to parse JSON file' };
    }
  }

  /**
   * Serializes current in-memory database to formatted JSON string
   */
  exportRecordsJson(): string {
    return JSON.stringify(this.records(), null, 2);
  }

  /**
   * Saves or updates a record employee-wise and month/year-wise
   */
  saveRecord(record: SheetRecord): Observable<SheetRecord> {
    const employeeName = record.employeeName.trim();
    const monthYear = record.monthYear.trim().toUpperCase();

    const current = { ...this.records() };
    if (!current[employeeName]) {
      current[employeeName] = {};
    }

    const updatedRecord: SheetRecord = {
      ...record,
      employeeName,
      monthYear,
      status: record.status || 'Pending',
      updatedAt: new Date().toISOString()
    };

    current[employeeName][monthYear] = updatedRecord;
    this.records.set(current);
    this.saveToLocalCache(current);

    if (typeof window === 'undefined' || !window.location || !window.location.origin || window.location.origin === 'null') {
      return of(updatedRecord);
    }

    const apiUrl = `${window.location.origin}/api/records`;
    const fnUrl = `${window.location.origin}/.netlify/functions/records`;

    return this.http.post<{ success?: boolean; data?: SheetRecord }>(apiUrl, updatedRecord).pipe(
      map(res => (res && res.data) ? res.data : updatedRecord),
      catchError(() => {
        return this.http.post<{ success?: boolean; data?: SheetRecord }>(fnUrl, updatedRecord).pipe(
          map(res => (res && res.data) ? res.data : updatedRecord),
          catchError(() => of(updatedRecord))
        );
      })
    );
  }

  /**
   * Get a specific record by employee and month
   */
  getRecord(employeeName: string, monthYear: string): SheetRecord | null {
    const db = this.records();
    const emp = db[employeeName.trim()];
    if (!emp) return null;
    return emp[monthYear.trim().toUpperCase()] || null;
  }

  /**
   * Convert nested database into flat array for table/card view
   */
  getAllRecordsFlat(): SheetRecord[] {
    const db = this.records();
    const list: SheetRecord[] = [];

    for (const empName of Object.keys(db)) {
      const months = db[empName];
      for (const mYear of Object.keys(months)) {
        list.push(months[mYear]);
      }
    }

    return list.sort((a, b) => {
      const tA = a.updatedAt ? new Date(a.updatedAt).getTime() : 0;
      const tB = b.updatedAt ? new Date(b.updatedAt).getTime() : 0;
      return tB - tA;
    });
  }
}
