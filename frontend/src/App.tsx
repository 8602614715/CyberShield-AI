import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ComponentType } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { CircleMarker, MapContainer, Popup, TileLayer } from "react-leaflet";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const REFRESH_INTERVAL_MS = 15000;
const AUTO_SCROLL_STEP = 1;
const AUTO_SCROLL_INTERVAL_MS = 80;
const CHART_COLORS = ["#22d3ee", "#818cf8", "#fbbf24", "#34d399", "#fb7185", "#a78bfa"];

const NAV_SECTIONS = [
  { id: "section-overview", label: "Overview" },
  { id: "section-operations", label: "Operations" },
  { id: "section-chatbot", label: "Chatbot" },
  { id: "section-geo", label: "Geo map" },
  { id: "section-analytics", label: "Analytics" },
  { id: "section-alerts", label: "Alerts & feed" },
] as const;
const INDIA_CENTER: [number, number] = [20.5937, 78.9629];
const INVALID_LOCATION_NAMES = new Set([
  "",
  "unknown",
  "india",
  "ai",
  "cyber fraud",
  "fraud",
  "single day",
  "north korea",
  "south korea",
  "united states",
  "usa",
  "uk",
  "united kingdom",
]);

const LeafletMapContainer = MapContainer as unknown as ComponentType<Record<string, unknown>>;
const LeafletTileLayer = TileLayer as unknown as ComponentType<Record<string, unknown>>;
const LeafletCircleMarker = CircleMarker as unknown as ComponentType<Record<string, unknown>>;
const LeafletPopup = Popup as unknown as ComponentType<Record<string, unknown>>;

type Report = {
  report_id?: string;
  title: string;
  url?: string;
  location: string;
  type: string;
  lat?: number;
  lng?: number;
  created_at?: string;
  risk_score?: number;
  risk_level?: string;
  ai_confidence?: number;
  model_used?: string;
  ai_explanation?: string;
  created_by?: string;
  status?: string;
  analyst_notes?: string;
  updated_at?: string;
  entity_summary?: EntitySummary;
  entities_flat?: string[];
  shared_evidence?: string[];
  shared_evidence_count?: number;
};

type AggregateStat = {
  _id: string;
  count: number;
};

type DashboardForm = {
  title: string;
  location: string;
  url: string;
  status: string;
  analyst_notes: string;
};

type MapReport = {
  title: string;
  location: string;
  type: string;
  lat?: number;
  lng?: number;
  risk_score?: number;
  risk_level?: string;
};

type MapPoint = {
  location: string;
  count: number;
  types: string[];
  lat: number;
  lng: number;
};

type CurrentUser = {
  name: string;
  email: string;
  role: string;
};

type AuthMode = "login" | "register";

type ChatMessage = {
  role: "user" | "assistant";
  text: string;
};

type AnalyzeResponse = {
  analysis: {
    predicted_type: string;
    confidence: number;
    risk_score: number;
    risk_level: string;
    model_used: string;
    explanation: string;
    url?: string;
  };
  entities?: EntitySummary;
};

type ReportUpdatePayload = {
  status: string;
  analyst_notes: string;
};

type EntitySummary = {
  phones?: string[];
  emails?: string[];
  upi_ids?: string[];
  urls?: string[];
  domains?: string[];
  keywords?: string[];
};

type RelatedLinksResponse = {
  report_id: string;
  entity_summary: EntitySummary;
  related_reports: Report[];
};

type PredictedHotspot = {
  location: string;
  recent_incidents: number;
  predicted_next_week: number;
  trend: string;
};

type RiskTrendResponse = {
  predicted_hotspots: PredictedHotspot[];
};

type SectionId = (typeof NAV_SECTIONS)[number]["id"];

function normalizeLocation(location: string) {
  return location.trim().toLowerCase();
}

function isValidCityLikeLocation(location: string) {
  return !INVALID_LOCATION_NAMES.has(normalizeLocation(location));
}

function isWithinIndiaBounds(lat: number, lng: number) {
  return lat >= 6 && lat <= 38 && lng >= 68 && lng <= 98;
}

function prettyLocation(location: string) {
  const normalized = normalizeLocation(location);
  if (!normalized) {
    return "Unknown";
  }
  return normalized
    .split(" ")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatPercent(value?: number) {
  if (typeof value !== "number") {
    return "N/A";
  }
  return `${Math.round(value * 100)}%`;
}

function initialsFromName(name: string, email: string) {
  const trimmed = name?.trim();
  if (trimmed) {
    const parts = trimmed.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[0].charAt(0)}${parts[1].charAt(0)}`.toUpperCase();
    }
    return trimmed.slice(0, 2).toUpperCase();
  }
  return email.slice(0, 2).toUpperCase();
}

function prettyModel(model?: string) {
  if (!model) {
    return "Unknown source";
  }
  if (model === "phishing_xgbclassifier") {
    return "Phishing XGBoost";
  }
  if (model === "spam_roberta") {
    return "Spam RoBERTa";
  }
  if (model === "trained_text_model") {
    return "Text ML model";
  }
  return "Rule engine";
}

function prettyStatus(status?: string) {
  const value = status?.trim();
  if (!value) {
    return "New";
  }
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function buildRecommendation(type: string, riskLevel: string) {
  if (type === "phishing") {
    return "Do not click the link or share credentials. Escalate the case and block the domain if confirmed.";
  }
  if (type === "spam") {
    return "Avoid replying or sharing personal data. Mark it for monitoring and preserve the original message.";
  }
  if (riskLevel === "high" || riskLevel === "critical") {
    return "Treat this as a priority case, preserve evidence, and review related reports for the same pattern.";
  }
  return "Keep the case under review and add analyst notes if more evidence appears.";
}

function entityItems(summary?: EntitySummary | null) {
  if (!summary) {
    return [] as Array<{ label: string; values: string[] }>;
  }
  return [
    { label: "Phone", values: summary.phones ?? [] },
    { label: "Email", values: summary.emails ?? [] },
    { label: "UPI", values: summary.upi_ids ?? [] },
    { label: "URL", values: summary.urls ?? [] },
    { label: "Domain", values: summary.domains ?? [] },
    { label: "Keyword", values: summary.keywords ?? [] },
  ].filter((item) => item.values.length > 0);
}

function extractUrl(text: string) {
  const match = text.match(/(https?:\/\/[^\s]+|www\.[^\s]+)/i);
  return match ? match[0] : "";
}

function formatHttpDetail(detail: unknown): string {
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (item && typeof item === "object" && "msg" in item) {
          return String((item as { msg: string }).msg);
        }
        return JSON.stringify(item);
      })
      .join(", ");
  }
  if (detail && typeof detail === "object" && "msg" in detail) {
    return String((detail as { msg: string }).msg);
  }
  return "Request failed";
}

function App() {
  const [reports, setReports] = useState<Report[]>([]);
  const [mapReports, setMapReports] = useState<MapReport[]>([]);
  const [alerts, setAlerts] = useState<AggregateStat[]>([]);
  const [riskTrends, setRiskTrends] = useState<PredictedHotspot[]>([]);
  const [form, setForm] = useState<DashboardForm>({
    title: "",
    location: "",
    url: "",
    status: "new",
    analyst_notes: "",
  });
  const [locationSuggestions, setLocationSuggestions] = useState<string[]>([]);
  const [geoHint, setGeoHint] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isReportFeedHovered, setIsReportFeedHovered] = useState(false);
  const reportListRef = useRef<HTMLDivElement | null>(null);
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [loginForm, setLoginForm] = useState({ email: "", password: "" });
  const [registerForm, setRegisterForm] = useState({
    name: "",
    email: "",
    password: "",
    role: "viewer",
  });
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionId>("section-overview");
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [urlAnalysisInput, setUrlAnalysisInput] = useState("");
  const [urlContextInput, setUrlContextInput] = useState("");
  const [urlCardLoading, setUrlCardLoading] = useState(false);
  const [urlCardResult, setUrlCardResult] = useState<AnalyzeResponse["analysis"] | null>(null);
  const [urlCardEntities, setUrlCardEntities] = useState<EntitySummary | null>(null);
  const [reportSearch, setReportSearch] = useState("");
  const [reportTypeFilter, setReportTypeFilter] = useState("all");
  const [reportRiskFilter, setReportRiskFilter] = useState("all");
  const [reportStatusFilter, setReportStatusFilter] = useState("all");
  const [selectedReportId, setSelectedReportId] = useState("");
  const [caseStatus, setCaseStatus] = useState("new");
  const [caseNotes, setCaseNotes] = useState("");
  const [caseSaving, setCaseSaving] = useState(false);
  const [relatedLoading, setRelatedLoading] = useState(false);
  const [relatedLinks, setRelatedLinks] = useState<RelatedLinksResponse | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      text: "Paste a suspicious message or URL. I will run the right detection models and explain the fraud risk in plain language.",
    },
  ]);

  const fetchJson = useCallback(
    async <T,>(path: string): Promise<T> => {
      const response = await fetch(`${API_BASE}${path}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      if (response.status === 401) {
        localStorage.removeItem("token");
        setToken("");
        setCurrentUser(null);
        setError("Your session expired. Please log in again.");
        throw new Error("Unauthorized");
      }

      if (!response.ok) {
        throw new Error(`Request failed for ${path}`);
      }
      return response.json() as Promise<T>;
    },
    [token]
  );

  const fetchData = useCallback(async () => {
    if (!token) {
      return;
    }

    try {
      setLoading(true);
      setError("");
      const [meData, reportsData, mapData, alertsData, riskTrendData] = await Promise.all([
        fetchJson<CurrentUser>("/auth/me"),
        fetchJson<Report[]>("/reports"),
        fetchJson<MapReport[]>("/reports/map"),
        fetchJson<AggregateStat[]>("/alerts"),
        fetchJson<RiskTrendResponse>("/api/predict/risk_trend").catch(() => ({ predicted_hotspots: [] })),
      ]);

      setCurrentUser(meData);
      setReports(reportsData);
      setMapReports(mapData);
      setAlerts(alertsData);
      setRiskTrends(riskTrendData?.predicted_hotspots ?? []);
      setLastUpdated(new Date());
    } catch (caughtError) {
      if (caughtError instanceof Error && caughtError.message === "Unauthorized") {
        return;
      }
      if (token) {
        setError("Unable to load dashboard data. Check that the FastAPI server is running.");
      }
    } finally {
      setLoading(false);
    }
  }, [fetchJson, token]);

  const loadLocationSuggestions = useCallback(
    async (latitude: number, longitude: number) => {
      if (!token) {
        return;
      }
      try {
        const res = await fetch(
          `${API_BASE}/geo/suggestions?lat=${encodeURIComponent(latitude)}&lon=${encodeURIComponent(longitude)}`,
          { headers: { Authorization: `Bearer ${token}` } },
        );
        if (res.status === 401) {
          localStorage.removeItem("token");
          setToken("");
          setCurrentUser(null);
          return;
        }
        if (!res.ok) {
          setGeoHint("Could not load location suggestions. Type a city manually.");
          return;
        }
        const data = (await res.json()) as { suggestions?: string[]; reverse_geocoded?: boolean };
        setLocationSuggestions(Array.isArray(data.suggestions) ? data.suggestions : []);
        setGeoHint(
          data.reverse_geocoded
            ? "Suggestions use your area plus the nearest major cities."
            : "Pick a suggested city or enter your own (reverse geocoding was unavailable).",
        );
      } catch {
        setGeoHint("Could not load location suggestions.");
      }
    },
    [token],
  );

  useEffect(() => {
    if (!token) {
      setLocationSuggestions([]);
      setGeoHint("");
      return;
    }

    if (!navigator.geolocation) {
      setGeoHint("Geolocation not supported — type a location manually.");
      void loadLocationSuggestions(INDIA_CENTER[0], INDIA_CENTER[1]);
      return;
    }

    setGeoHint("Detecting your location for suggestions…");
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        void loadLocationSuggestions(pos.coords.latitude, pos.coords.longitude);
      },
      () => {
        setGeoHint("Location permission denied — showing nationwide city suggestions.");
        void loadLocationSuggestions(INDIA_CENTER[0], INDIA_CENTER[1]);
      },
      { enableHighAccuracy: false, timeout: 12_000, maximumAge: 300_000 },
    );
  }, [token, loadLocationSuggestions]);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }

    fetchData();
    const intervalId = window.setInterval(fetchData, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(intervalId);
  }, [fetchData, token]);

  useEffect(() => {
    const reportList = reportListRef.current;
    if (!reportList || isReportFeedHovered || reports.length < 2) {
      return;
    }

    const intervalId = window.setInterval(() => {
      const maxScrollTop = reportList.scrollHeight - reportList.clientHeight;
      if (maxScrollTop <= 0) {
        return;
      }

      const nextScrollTop = reportList.scrollTop + AUTO_SCROLL_STEP;
      reportList.scrollTop = nextScrollTop >= maxScrollTop ? 0 : nextScrollTop;
    }, AUTO_SCROLL_INTERVAL_MS);

    return () => window.clearInterval(intervalId);
  }, [isReportFeedHovered, reports]);

  useEffect(() => {
    if (!reports.length) {
      setSelectedReportId("");
      setCaseStatus("new");
      setCaseNotes("");
      return;
    }

    const activeReport = reports.find((report) => report.report_id === selectedReportId) ?? reports[0];
    if (activeReport.report_id !== selectedReportId) {
      setSelectedReportId(activeReport.report_id ?? "");
    }
    setCaseStatus(activeReport.status ?? "new");
    setCaseNotes(activeReport.analyst_notes ?? "");
  }, [reports, selectedReportId]);

  useEffect(() => {
    const targetReportId = selectedReportId || reports[0]?.report_id || "";
    if (!token || !targetReportId) {
      setRelatedLinks(null);
      return;
    }

    let cancelled = false;
    setRelatedLoading(true);

    void (async () => {
      try {
        const response = await fetch(`${API_BASE}/reports/${targetReportId}/links`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) {
          if (response.status === 401) {
            localStorage.removeItem("token");
            setToken("");
            setCurrentUser(null);
          }
          throw new Error("Unable to load report links");
        }
        const data = (await response.json()) as RelatedLinksResponse;
        if (!cancelled) {
          setRelatedLinks(data);
        }
      } catch {
        if (!cancelled) {
          setRelatedLinks(null);
        }
      } finally {
        if (!cancelled) {
          setRelatedLoading(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [selectedReportId, reports, token]);

  async function handleSubmit() {
    if (!form.title || !form.location) {
      setError("Please fill in title and location before adding a report.");
      return;
    }

    try {
      setSubmitting(true);
      setError("");

      const response = await fetch(`${API_BASE}/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(form),
      });

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem("token");
          setToken("");
          throw new Error("Unauthorized");
        }
        throw new Error("Failed to save report");
      }

      setForm({ title: "", location: "", url: "", status: "new", analyst_notes: "" });
      await fetchData();
    } catch {
      setError("Unable to save the report right now.");
    } finally {
      setSubmitting(false);
    }
  }

  const summary = useMemo(() => {
    const lastDayCutoff = new Date();
    lastDayCutoff.setDate(lastDayCutoff.getDate() - 1);

    const phishingCases = reports.filter((report) => report.type?.toLowerCase() === "phishing").length;
    const financeCases = reports.filter((report) => report.type?.toLowerCase() === "finance").length;
    const recentReports = reports.filter((report) => {
      if (!report.created_at) {
        return false;
      }
      return new Date(report.created_at) >= lastDayCutoff;
    }).length;

    return {
      total_reports: reports.length,
      phishing_cases: phishingCases,
      finance_cases: financeCases,
      recent_reports: recentReports,
    };
  }, [reports]);

  const typeStats = useMemo(() => {
    const counts = new Map<string, number>();
    for (const report of reports) {
      const type = report.type || "other";
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([key, count]) => ({ _id: key, count }))
      .sort((a, b) => b.count - a.count || a._id.localeCompare(b._id));
  }, [reports]);

  const locationStats = useMemo(() => {
    const counts = new Map<string, number>();
    for (const report of reports) {
      const normalized = normalizeLocation(report.location || "");
      if (!isValidCityLikeLocation(normalized)) {
        continue;
      }
      counts.set(normalized, (counts.get(normalized) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([key, count]) => ({ _id: prettyLocation(key), count }))
      .sort((a, b) => b.count - a.count || a._id.localeCompare(b._id))
      .slice(0, 6);
  }, [reports]);

  const timelineStats = useMemo(() => {
    const counts = new Map<string, number>();
    const days = 7;
    const now = new Date();

    for (let dayOffset = days - 1; dayOffset >= 0; dayOffset -= 1) {
      const date = new Date(now);
      date.setHours(0, 0, 0, 0);
      date.setDate(now.getDate() - dayOffset);
      const key = date.toISOString().slice(0, 10);
      counts.set(key, 0);
    }

    for (const report of reports) {
      if (!report.created_at) {
        continue;
      }
      const key = new Date(report.created_at).toISOString().slice(0, 10);
      if (counts.has(key)) {
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }

    return Array.from(counts.entries()).map(([date, count]) => ({
      date: new Date(date).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
      }),
      count,
    }));
  }, [reports]);

  const mapPoints = useMemo(() => {
    const grouped = new Map<string, MapPoint>();

    for (const report of mapReports) {
      const normalized = normalizeLocation(report.location || "");
      if (!isValidCityLikeLocation(normalized)) {
        continue;
      }
      if (typeof report.lat !== "number" || typeof report.lng !== "number") {
        continue;
      }
      if (!isWithinIndiaBounds(report.lat, report.lng)) {
        continue;
      }

      const existing = grouped.get(normalized);
      if (existing) {
        existing.count += 1;
        if (!existing.types.includes(report.type)) {
          existing.types.push(report.type);
        }
      } else {
        grouped.set(normalized, {
          location: prettyLocation(normalized),
          count: 1,
          types: report.type ? [report.type] : [],
          lat: report.lat,
          lng: report.lng,
        });
      }
    }

    return Array.from(grouped.values()).sort(
      (a, b) => b.count - a.count || a.location.localeCompare(b.location)
    );
  }, [mapReports]);

  const pieData = typeStats.map((item, index) => ({
    name: item._id,
    value: item.count,
    fill: CHART_COLORS[index % CHART_COLORS.length],
  }));

  const barData = locationStats.map((item) => ({
    location: item._id,
    count: item.count,
  }));

  const strongestHotspot = mapPoints.reduce<MapPoint | null>(
    (current, point) => (!current || point.count > current.count ? point : current),
    null
  );

  const filteredReports = useMemo(() => {
    const searchValue = reportSearch.trim().toLowerCase();
    return reports.filter((report) => {
      const matchesSearch =
        !searchValue ||
        report.title.toLowerCase().includes(searchValue) ||
        (report.location ?? "").toLowerCase().includes(searchValue) ||
        (report.url ?? "").toLowerCase().includes(searchValue) ||
        (report.analyst_notes ?? "").toLowerCase().includes(searchValue);
      const matchesType = reportTypeFilter === "all" || report.type === reportTypeFilter;
      const matchesRisk = reportRiskFilter === "all" || (report.risk_level ?? "low") === reportRiskFilter;
      const matchesStatus = reportStatusFilter === "all" || (report.status ?? "new") === reportStatusFilter;
      return matchesSearch && matchesType && matchesRisk && matchesStatus;
    });
  }, [reports, reportRiskFilter, reportSearch, reportStatusFilter, reportTypeFilter]);

  const selectedReport =
    filteredReports.find((report) => report.report_id === selectedReportId) ??
    reports.find((report) => report.report_id === selectedReportId) ??
    filteredReports[0] ??
    reports[0] ??
    null;

  async function handleLogin() {
    if (!loginForm.email || !loginForm.password) {
      setError("Enter your email and password to continue.");
      return;
    }

    setError("");

    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...loginForm, email: loginForm.email.trim().toLowerCase() }),
    });

    const data = (await res.json()) as { access_token?: string; detail?: unknown };
    if (res.ok && data.access_token) {
      localStorage.setItem("token", data.access_token);
      setToken(data.access_token);
      setLoginForm({ email: "", password: "" });
      setError("");
      setLoading(true);
    } else {
      setError(formatHttpDetail(data.detail) || "Login failed");
    }
  }

  async function handleRegister() {
    if (!registerForm.name || !registerForm.email || !registerForm.password) {
      setError("Enter your name, email, and password to create an account.");
      return;
    }

    setError("");

    const res = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...registerForm,
        email: registerForm.email.trim().toLowerCase(),
      }),
    });

    const data = (await res.json()) as { detail?: unknown };
    if (res.ok) {
      setLoginForm({
        email: registerForm.email.trim().toLowerCase(),
        password: registerForm.password,
      });
      setRegisterForm({
        name: "",
        email: "",
        password: "",
        role: "viewer",
      });
      setAuthMode("login");
      setError("Registration successful. Log in with your new account.");
    } else {
      setError(formatHttpDetail(data.detail) || "Registration failed");
    }
  }

  async function handleChatAnalyze() {
    if (!chatInput.trim()) {
      return;
    }

    const prompt = chatInput.trim();
    setChatMessages((current) => [...current, { role: "user", text: prompt }]);
    setChatInput("");
    setChatLoading(true);

    try {
      const detectedUrl = extractUrl(prompt);
      const endpoint = detectedUrl ? "/ai/analyze-url" : "/ai/analyze";
      const payload = detectedUrl
        ? {
            url: detectedUrl,
            context: prompt,
          }
        : {
            title: prompt,
            location: "",
            url: "",
          };

      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem("token");
          setToken("");
          setCurrentUser(null);
          throw new Error("Unauthorized");
        }
        throw new Error("Analysis failed");
      }

      const data = (await response.json()) as AnalyzeResponse;
      const analysis = data.analysis;
      const reply = [
        `Type: ${analysis.predicted_type}`,
        `Risk: ${analysis.risk_level} (${analysis.risk_score}/100)`,
        `Confidence: ${formatPercent(analysis.confidence)}`,
        `Engine: ${prettyModel(analysis.model_used)}`,
        analysis.url ? `URL: ${analysis.url}` : "",
        `Why: ${analysis.explanation}`,
        `Recommendation: ${buildRecommendation(analysis.predicted_type, analysis.risk_level)}`,
      ]
        .filter(Boolean)
        .join("\n");

      setChatMessages((current) => [...current, { role: "assistant", text: reply }]);
    } catch (caughtError) {
      const reply =
        caughtError instanceof Error && caughtError.message === "Unauthorized"
          ? "Your session expired. Please log in again."
          : "I could not analyze that message right now. Check that the backend is running.";
      setChatMessages((current) => [...current, { role: "assistant", text: reply }]);
    } finally {
      setChatLoading(false);
    }
  }

  async function handleUrlCardAnalyze() {
    const normalizedUrl = urlAnalysisInput.trim();
    if (!normalizedUrl) {
      setError("Enter a suspicious URL to analyze.");
      return;
    }

    setUrlCardLoading(true);
    setError("");
    try {
      const response = await fetch(`${API_BASE}/ai/analyze-url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          url: normalizedUrl,
          context: urlContextInput.trim(),
        }),
      });

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem("token");
          setToken("");
          setCurrentUser(null);
          throw new Error("Unauthorized");
        }
        throw new Error("URL analysis failed");
      }

      const data = (await response.json()) as AnalyzeResponse;
      setUrlCardResult(data.analysis);
      setUrlCardEntities(data.entities ?? null);
    } catch (caughtError) {
      if (caughtError instanceof Error && caughtError.message === "Unauthorized") {
        setError("Your session expired. Please log in again.");
      } else {
        setError("Unable to analyze the URL right now.");
      }
      setUrlCardResult(null);
      setUrlCardEntities(null);
    } finally {
      setUrlCardLoading(false);
    }
  }

  async function handleCaseUpdate() {
    if (!selectedReport?.report_id) {
      return;
    }

    setCaseSaving(true);
    setError("");
    try {
      const response = await fetch(`${API_BASE}/reports/${selectedReport.report_id}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          status: caseStatus,
          analyst_notes: caseNotes,
        } satisfies ReportUpdatePayload),
      });

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem("token");
          setToken("");
          setCurrentUser(null);
          throw new Error("Unauthorized");
        }
        const payload = (await response.json()) as { detail?: unknown };
        throw new Error(formatHttpDetail(payload.detail));
      }

      await fetchData();
    } catch (caughtError) {
      if (caughtError instanceof Error && caughtError.message === "Unauthorized") {
        setError("Your session expired. Please log in again.");
      } else {
        setError(caughtError instanceof Error ? caughtError.message : "Unable to update the case.");
      }
    } finally {
      setCaseSaving(false);
    }
  }

  function handleLogout() {
    localStorage.removeItem("token");
    setToken("");
    setCurrentUser(null);
    setError("");
  }

  function selectSection(sectionId: SectionId) {
    setActiveSection(sectionId);
    setSidebarOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  if (!token) {
    return (
      <div className="app-root">
        <a className="skip-link" href="#auth-main">
          Skip to sign in
        </a>
        <div className="app-bg" aria-hidden="true" />
        <div className="auth-page">
          <div className="auth-branding">
            <div className="auth-branding-inner">
              <div className="auth-logo-row">
                <div className="auth-logo-mark" aria-hidden="true">
                  <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path
                      d="M12 3 4 9v12h16V9l-8-6Z"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      strokeLinejoin="round"
                    />
                    <path d="m9 12 2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                </div>
              </div>
              <h1>CyberFraud Intelligence</h1>
              <p className="auth-lead">
                Enterprise-style triage for phishing URLs, spam messages, and payment fraud — with geospatial reporting
                tuned for Indian metro coverage.
              </p>
              <ul className="auth-checklist">
                <li>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path
                      d="M20 6 9 17l-5-5"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  RoBERTa spam, phishing URL models, and rule fallbacks in one pipeline
                </li>
                <li>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path
                      d="M20 6 9 17l-5-5"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  Live map, alerts, and analyst chat wired to your FastAPI backend
                </li>
              </ul>
            </div>
          </div>
          <div className="auth-form-panel" id="auth-main">
            <main className="auth-card">
              <p className="eyebrow">Secure access</p>
              <h1>{authMode === "login" ? "Sign in" : "Create account"}</h1>
              <p className="hero-text">
                {authMode === "login"
                  ? "Use your credentials to open the intelligence workspace and submit protected incident reports."
                  : "Create a user record in MongoDB to access dashboards, APIs, and collaborative reporting."}
              </p>

              {error ? <div className="banner banner-error">{error}</div> : null}

              <div className="form-grid">
                {authMode === "register" ? (
                  <>
                    <label htmlFor="reg-name">
                      <span>Name</span>
                      <input
                        id="reg-name"
                        autoComplete="name"
                        placeholder="Your name"
                        value={registerForm.name}
                        onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })}
                      />
                    </label>
                    <label htmlFor="reg-email">
                      <span>Email</span>
                      <input
                        id="reg-email"
                        autoComplete="email"
                        placeholder="you@example.com"
                        value={registerForm.email}
                        onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })}
                      />
                    </label>
                    <label htmlFor="reg-password">
                      <span>Password</span>
                      <input
                        id="reg-password"
                        autoComplete="new-password"
                        placeholder="Create password"
                        type="password"
                        value={registerForm.password}
                        onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                      />
                    </label>
                    <label htmlFor="reg-role">
                      <span>Role</span>
                      <select
                        id="reg-role"
                        value={registerForm.role}
                        onChange={(e) => setRegisterForm({ ...registerForm, role: e.target.value || "viewer" })}
                      >
                        <option value="viewer">Viewer</option>
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </label>
                  </>
                ) : (
                  <>
                    <label htmlFor="login-email">
                      <span>Email</span>
                      <input
                        id="login-email"
                        autoComplete="email"
                        placeholder="you@example.com"
                        value={loginForm.email}
                        onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })}
                      />
                    </label>
                    <label htmlFor="login-password">
                      <span>Password</span>
                      <input
                        id="login-password"
                        autoComplete="current-password"
                        placeholder="Enter password"
                        type="password"
                        value={loginForm.password}
                        onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                      />
                    </label>
                  </>
                )}
              </div>

              <button
                className="primary-button"
                type="button"
                onClick={authMode === "login" ? handleLogin : handleRegister}
              >
                {authMode === "login" ? "Sign in" : "Create account"}
              </button>

              <button
                className="logout-button"
                onClick={() => {
                  setError("");
                  setAuthMode(authMode === "login" ? "register" : "login");
                }}
                type="button"
              >
                {authMode === "login" ? "Need an account? Register" : "Already registered? Sign in"}
              </button>
            </main>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-root">
      <a className="skip-link" href="#section-overview">
        Skip to content
      </a>
      <div className="app-bg" aria-hidden="true" />
      <div
        className={`sidebar-overlay ${sidebarOpen ? "visible" : ""}`}
        onClick={() => setSidebarOpen(false)}
        role="presentation"
      />
      <div className="app-shell">
        <aside className={`app-sidebar ${sidebarOpen ? "open" : ""}`} aria-label="Primary navigation">
          <div className="sidebar-brand">
            <div className="sidebar-brand-mark" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                <path
                  d="M12 3 4 9v12h16V9l-8-6Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                />
                <path d="m9 12 2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
            </div>
            <div className="sidebar-brand-text">
              <strong>CyberFraud</strong>
              <span>Intelligence</span>
            </div>
          </div>
          <nav className="sidebar-nav">
            {NAV_SECTIONS.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`nav-link ${activeSection === item.id ? "active" : ""}`}
                onClick={() => selectSection(item.id)}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.5" />
                  <path
                    d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                </svg>
                {item.label}
              </button>
            ))}
          </nav>
          <div className="sidebar-footer">Secured session · Auto-refresh every 15s</div>
        </aside>
        <div className="app-main">
          <header className="app-topbar">
            <div className="topbar-left">
              <button
                type="button"
                className="menu-toggle"
                onClick={() => setSidebarOpen(true)}
                aria-label="Open navigation menu"
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              <div className="topbar-title-block">
                <h1>Command center</h1>
                <p>Real-time fraud intelligence</p>
              </div>
            </div>
            <div className="topbar-right">
              <div className="sync-badge">
                <span className="sync-dot" aria-hidden="true" />
                {lastUpdated ? `Synced ${lastUpdated.toLocaleTimeString()}` : "Connecting…"}
              </div>
              {currentUser ? (
                <div className="user-chip">
                  <div className="user-avatar" aria-hidden="true">
                    {initialsFromName(currentUser.name, currentUser.email)}
                  </div>
                  <div className="user-chip-text">
                    <strong>{currentUser.name || currentUser.email}</strong>
                    <span>{currentUser.role}</span>
                  </div>
                </div>
              ) : null}
              <button type="button" className="btn-ghost" onClick={handleLogout}>
                Logout
              </button>
            </div>
          </header>
          <main className="dashboard">
            {activeSection === "section-overview" && (
            <section id="section-overview" className="section-block">
              <div className="welcome-strip">
                <div>
                  <p className="eyebrow">Overview</p>
                  <h2>Fraud intelligence workspace</h2>
                  <p className="hero-text">
                    Analyze suspicious messages and URLs with the chatbot, then monitor live reports, hotspots, and trends
                    across your operation.
                  </p>
                </div>
                <div className="welcome-meta">
                  <div className="status-pill">
                    <span className="status-dot" />
                    Auto refresh every 15s
                  </div>
                  <p className="status-text">
                    {lastUpdated ? `Last updated ${lastUpdated.toLocaleTimeString()}` : "Waiting for first sync"}
                  </p>
                </div>
              </div>

              {error ? <div className="banner banner-error">{error}</div> : null}

              <div className="stats-grid">
          <article className="stat-card">
            <p className="stat-label">Total Reports</p>
            <h2>{summary.total_reports}</h2>
            <span className="stat-footnote">Live report volume</span>
          </article>

          <article className="stat-card">
            <p className="stat-label">Phishing Cases</p>
            <h2>{summary.phishing_cases}</h2>
            <span className="stat-footnote">Classified from report titles</span>
          </article>

          <article className="stat-card">
            <p className="stat-label">Finance Cases</p>
            <h2>{summary.finance_cases}</h2>
            <span className="stat-footnote">Loan and payment related fraud</span>
          </article>

          <article className="stat-card">
            <p className="stat-label">Last 24 Hours</p>
            <h2>{summary.recent_reports}</h2>
            <span className="stat-footnote">Recent incoming reports</span>
          </article>
              </div>
              <section className="panel about-panel">
                <div className="panel-heading">
                  <p className="panel-kicker">About</p>
                  <h3>About this application</h3>
                </div>
                <p className="hero-text">
                  CyberFraud Intelligence helps teams collect incidents, run chatbot-led scam analysis, and visualize
                  fraud patterns by location and risk severity using your FastAPI + MongoDB backend.
                </p>
              </section>
            </section>
            )}

            {activeSection === "section-operations" && (
            <section id="section-operations" className="section-block content-grid analytics-grid">
          <section className="panel panel-form">
            <div className="panel-heading">
              <p className="panel-kicker">Add Incident</p>
              <h3>Report a new case</h3>
            </div>

            <div className="form-grid">
              <label>
                <span>Title</span>
                <input
                  placeholder="Fake OTP call from bank"
                  value={form.title}
                  onChange={(event) => setForm({ ...form, title: event.target.value })}
                />
              </label>

              <label htmlFor="incident-location">
                <span>Location</span>
                <input
                  id="incident-location"
                  name="location"
                  placeholder="Start typing or pick a suggestion"
                  list="incident-location-suggestions"
                  autoComplete="address-level2"
                  value={form.location}
                  onChange={(event) => setForm({ ...form, location: event.target.value })}
                />
              </label>
              <label>
                <span>Suspicious URL</span>
                <input
                  placeholder="https://suspicious-domain.example/login"
                  value={form.url}
                  onChange={(event) => setForm({ ...form, url: event.target.value })}
                />
              </label>
              <label>
                <span>Initial status</span>
                <select
                  value={form.status}
                  onChange={(event) => setForm({ ...form, status: event.target.value })}
                >
                  <option value="new">New</option>
                  <option value="under_review">Under Review</option>
                  <option value="confirmed_fraud">Confirmed Fraud</option>
                  <option value="false_positive">False Positive</option>
                  <option value="closed">Closed</option>
                </select>
              </label>
              <label className="form-span-2">
                <span>Analyst notes</span>
                <textarea
                  rows={4}
                  placeholder="Add intake notes, evidence summary, or investigation context"
                  value={form.analyst_notes}
                  onChange={(event) => setForm({ ...form, analyst_notes: event.target.value })}
                />
              </label>
              <datalist id="incident-location-suggestions">
                {locationSuggestions.map((place) => (
                  <option key={place} value={place} />
                ))}
              </datalist>
              {geoHint ? <p className="geo-hint">{geoHint}</p> : null}
            </div>

            <button className="primary-button" onClick={handleSubmit} disabled={submitting}>
              {submitting ? "Saving..." : "Add Report"}
            </button>
          </section>

          <section className="panel panel-chart">
            <div className="panel-heading">
              <p className="panel-kicker">Volume Trend</p>
              <h3>Daily reports</h3>
            </div>

            <div className="chart-wrap">
              {loading ? (
                <div className="skeleton-block" role="status" aria-label="Loading chart" />
              ) : (
                <ResponsiveContainer width="100%" height={280}>
                  <LineChart data={timelineStats}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.12)" />
                    <XAxis dataKey="date" stroke="#94a3b8" />
                    <YAxis allowDecimals={false} stroke="#94a3b8" />
                    <Tooltip />
                    <Line
                      type="monotone"
                      dataKey="count"
                      stroke="#22d3ee"
                      strokeWidth={2.5}
                      dot={{ r: 4, fill: "#22d3ee" }}
                      activeDot={{ r: 6 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
          </section>
        </section>
            )}

        {activeSection === "section-chatbot" && (
        <section id="section-chatbot" className="section-block panel panel-chatbot lower-grid">
          <div className="panel-heading">
            <p className="panel-kicker">Chatbot</p>
            <h3>Fraud analysis chatbot</h3>
          </div>

          <div className="chatbot-shell">
            <div className="chatbot-banner">
              <div>
                <span className="chatbot-banner-label">Interactive triage</span>
                <strong>Paste a scam message, fake offer, or suspicious URL</strong>
              </div>
              <p>
                The chatbot routes text to spam and rule engines and sends links through the phishing URL model
                automatically.
              </p>
            </div>

            <div className="chatbot-messages">
              {chatMessages.map((message, index) => (
                <article
                  className={`chat-message chat-${message.role}`}
                  key={`${message.role}-${index}`}
                >
                  <span className="chat-role">
                    {message.role === "assistant" ? "Chatbot" : "You"}
                  </span>
                  <p>{message.text}</p>
                </article>
              ))}
              {chatLoading ? (
                <article className="chat-message chat-assistant">
                  <span className="chat-role">Chatbot</span>
                  <p>Analyzing the scam pattern...</p>
                </article>
              ) : null}
            </div>

            <div className="chatbot-input-row">
              <input
                className="chatbot-input"
                placeholder="Paste a suspicious message or URL like https://fake-bank-login.example"
                value={chatInput}
                onChange={(event) => setChatInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void handleChatAnalyze();
                  }
                }}
              />
              <button className="primary-button" onClick={() => void handleChatAnalyze()} disabled={chatLoading}>
                {chatLoading ? "Thinking..." : "Analyze"}
              </button>
            </div>

            <div className="chatbot-hint-row">
              <span className="chatbot-hint">Text scams route to the spam/text models.</span>
              <span className="chatbot-hint">Links route to the phishing URL model.</span>
            </div>

            <div className="url-analysis-card">
              <div className="panel-heading compact-heading">
                <div>
                  <p className="panel-kicker">URL Scan</p>
                  <h3>Dedicated link analysis</h3>
                </div>
              </div>

              <div className="form-grid">
                <label className="form-span-2">
                  <span>Suspicious URL</span>
                  <input
                    placeholder="https://secure-bank-login.example/verify"
                    value={urlAnalysisInput}
                    onChange={(event) => setUrlAnalysisInput(event.target.value)}
                  />
                </label>
                <label className="form-span-2">
                  <span>Context</span>
                  <textarea
                    rows={3}
                    placeholder="Optional message or reason why this URL looks suspicious"
                    value={urlContextInput}
                    onChange={(event) => setUrlContextInput(event.target.value)}
                  />
                </label>
              </div>

              <div className="url-analysis-actions">
                <button className="primary-button" onClick={() => void handleUrlCardAnalyze()} disabled={urlCardLoading}>
                  {urlCardLoading ? "Scanning..." : "Analyze URL"}
                </button>
              </div>

              {urlCardResult ? (
                <div className="url-analysis-result">
                  <div className="report-meta">
                    <span className="report-tag">{urlCardResult.predicted_type}</span>
                    <span className={`risk-badge risk-${urlCardResult.risk_level}`}>{urlCardResult.risk_level} risk</span>
                  </div>
                  <p className="url-analysis-line">
                    <strong>Confidence:</strong> {formatPercent(urlCardResult.confidence)}
                  </p>
                  <p className="url-analysis-line">
                    <strong>Model:</strong> {prettyModel(urlCardResult.model_used)}
                  </p>
                  {urlCardResult.url ? (
                    <p className="url-analysis-line">
                      <strong>URL:</strong> {urlCardResult.url}
                    </p>
                  ) : null}
                  <p className="url-analysis-line">
                    <strong>Recommendation:</strong> {buildRecommendation(urlCardResult.predicted_type, urlCardResult.risk_level)}
                  </p>
                  <p className="url-analysis-line">
                    <strong>Why:</strong> {urlCardResult.explanation}
                  </p>
                  {entityItems(urlCardEntities).length ? (
                    <div className="entity-block">
                      <strong className="entity-block-title">Extracted evidence</strong>
                      <div className="entity-grid">
                        {entityItems(urlCardEntities).map((group) => (
                          <div key={group.label} className="entity-group">
                            <span className="entity-label">{group.label}</span>
                            <div className="entity-tags">
                              {group.values.map((value) => (
                                <span key={`${group.label}-${value}`} className="entity-tag">
                                  {value}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
          </div>
        </section>
        )}

        {activeSection === "section-geo" && (
        <section id="section-geo" className="section-block panel panel-map lower-grid">
          <div className="panel-heading">
            <p className="panel-kicker">Geo Intelligence</p>
            <h3>Fraud map</h3>
          </div>

          <div className="map-shell">
            {loading ? (
              <p className="empty-state">Loading hotspot map...</p>
            ) : mapPoints.length === 0 ? (
              <div className="map-empty-state">
                <p className="empty-state">No mapped locations available yet.</p>
                <p className="map-empty-copy">
                  The current backend only exposes map rows when reports include `lat` and
                  `lng`, so run the scraper or add geocoded reports to populate this panel.
                </p>
              </div>
            ) : (
              <>
                <LeafletMapContainer
                  center={INDIA_CENTER}
                  zoom={4.6}
                  scrollWheelZoom={false}
                  className="fraud-map"
                >
                  <LeafletTileLayer
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                    url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                  />
                  {mapPoints.map((point) => (
                    <LeafletCircleMarker
                      key={`${point.location}-${point.lat}-${point.lng}`}
                      center={[point.lat, point.lng]}
                      radius={Math.min(26, 8 + point.count * 2.2)}
                      pathOptions={{
                        color: "#22d3ee",
                        fillColor: "#818cf8",
                        fillOpacity: 0.55,
                        weight: 2,
                      }}
                    >
                      <LeafletPopup>
                        <strong>{point.location}</strong>
                        <br />
                        Reports: {point.count}
                        <br />
                        Types: {point.types.join(", ")}
                      </LeafletPopup>
                    </LeafletCircleMarker>
                  ))}
                </LeafletMapContainer>

                <div className="map-summary">
                  <div className="map-highlight">
                    <span className="map-label">Strongest hotspot</span>
                    <strong>{strongestHotspot?.location ?? "Unknown"}</strong>
                    <p>
                      {strongestHotspot
                        ? `${strongestHotspot.count} reports across ${strongestHotspot.types.join(", ")}`
                        : "No hotspot data yet."}
                    </p>
                  </div>

                  <div className="map-list">
                    {mapPoints.slice(0, 5).map((point) => (
                      <div className="map-list-item" key={`${point.location}-${point.count}`}>
                        <span>{point.location}</span>
                        <strong>{point.count}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        </section>
        )}

        {activeSection === "section-analytics" && (
        <section id="section-analytics" className="section-block content-grid lower-grid analytics-grid">
          <section className="panel panel-chart">
            <div className="panel-heading">
              <p className="panel-kicker">Distribution</p>
              <h3>Scam type mix</h3>
            </div>

            <div className="chart-wrap">
              {loading ? (
                <div className="skeleton-block" role="status" aria-label="Loading chart" />
              ) : pieData.length === 0 ? (
                <p className="empty-state">No type data available yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={68}
                      outerRadius={104}
                      paddingAngle={4}
                    >
                      {pieData.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend verticalAlign="bottom" height={36} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </section>

          <section className="panel panel-chart">
            <div className="panel-heading">
              <p className="panel-kicker">Location Pulse</p>
              <h3>Top affected locations</h3>
            </div>

            <div className="chart-wrap">
              {loading ? (
                <div className="skeleton-block" role="status" aria-label="Loading chart" />
              ) : barData.length === 0 ? (
                <p className="empty-state">No location data available yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={barData} margin={{ top: 8, right: 8, left: 0, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.12)" />
                    <XAxis
                      dataKey="location"
                      stroke="#94a3b8"
                      interval={0}
                      angle={-20}
                      textAnchor="end"
                      height={56}
                    />
                    <YAxis allowDecimals={false} stroke="#94a3b8" />
                    <Tooltip />
                    <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                      {barData.map((entry, index) => (
                        <Cell key={`${entry.location}-${entry.count}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </section>
        </section>
        )}

        {activeSection === "section-alerts" && (
        <section id="section-alerts" className="section-block content-grid lower-grid">
          <section className="panel panel-alerts">
            <div className="panel-heading">
              <p className="panel-kicker">Escalation Watch</p>
              <h3>Location alerts</h3>
            </div>

            <div className="list-stack alerts-list">
              {alerts.length === 0 ? (
                <p className="empty-state">No locations have crossed the alert threshold yet.</p>
              ) : (
                alerts
                  .filter((alert) => isValidCityLikeLocation(alert._id))
                  .map((alert) => (
                  <div className="alert-item" key={`${alert._id}-${alert.count}`}>
                    <div>
                      <strong>{prettyLocation(alert._id)}</strong>
                      <p>High report activity detected for this location</p>
                    </div>
                    <span>{alert.count}</span>
                  </div>
                ))
              )}
            </div>

            <div className="panel-heading" style={{ marginTop: "32px", borderTop: "1px solid rgba(148, 163, 184, 0.12)", paddingTop: "24px" }}>
              <p className="panel-kicker">AI Forecast</p>
              <h3>Predicted risk hotspots</h3>
            </div>

            <div className="list-stack alerts-list">
              {riskTrends.length === 0 ? (
                <p className="empty-state">No risk hotspots predicted at the moment.</p>
              ) : (
                riskTrends.map((trend) => (
                  <div className="alert-item" key={`${trend.location}-${trend.recent_incidents}`}>
                    <div>
                      <strong>{prettyLocation(trend.location)} <span style={{color: "#ef4444"}}>📈</span></strong>
                      <p>Forecasted to reach {trend.predicted_next_week} incidents next week</p>
                    </div>
                    <span>{trend.recent_incidents} recent</span>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="panel panel-reports">
            <div className="panel-heading">
              <p className="panel-kicker">Live Feed</p>
              <h3>Recent reports</h3>
            </div>

            <div className="report-filters">
              <input
                className="filter-input"
                placeholder="Search title, URL, notes, or location"
                value={reportSearch}
                onChange={(event) => setReportSearch(event.target.value)}
              />
              <select value={reportTypeFilter} onChange={(event) => setReportTypeFilter(event.target.value)}>
                <option value="all">All types</option>
                <option value="phishing">Phishing</option>
                <option value="spam">Spam</option>
                <option value="finance">Finance</option>
                <option value="employment">Employment</option>
                <option value="payment fraud">Payment fraud</option>
                <option value="other">Other</option>
              </select>
              <select value={reportRiskFilter} onChange={(event) => setReportRiskFilter(event.target.value)}>
                <option value="all">All risks</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select value={reportStatusFilter} onChange={(event) => setReportStatusFilter(event.target.value)}>
                <option value="all">All statuses</option>
                <option value="new">New</option>
                <option value="under_review">Under Review</option>
                <option value="confirmed_fraud">Confirmed Fraud</option>
                <option value="false_positive">False Positive</option>
                <option value="closed">Closed</option>
              </select>
            </div>

            <div
              className="report-list"
              ref={reportListRef}
              onMouseEnter={() => setIsReportFeedHovered(true)}
              onMouseLeave={() => setIsReportFeedHovered(false)}
            >
              {loading ? (
                <p className="empty-state">Loading dashboard data...</p>
              ) : filteredReports.length === 0 ? (
                <p className="empty-state">No reports match the current search and filters.</p>
              ) : (
                filteredReports.map((report, index) => (
                  <article
                    className={`report-card selectable-report ${selectedReport?.report_id === report.report_id ? "report-card-active" : ""}`}
                    key={`${report.report_id ?? report.title}-${index}`}
                    onClick={() => setSelectedReportId(report.report_id ?? "")}
                  >
                    <div className="report-topline">
                      <span className="report-tag">{report.type}</span>
                      <span className="report-location">{prettyLocation(report.location)}</span>
                    </div>
                    <div className="report-meta">
                      <span className={`risk-badge risk-${report.risk_level ?? "low"}`}>
                        {report.risk_level ?? "low"} risk
                      </span>
                      <span className="case-status-badge">{prettyStatus(report.status)}</span>
                      <span className="report-ai-detail">
                        {prettyModel(report.model_used)} • {formatPercent(report.ai_confidence)}
                      </span>
                    </div>
                    <h4>{report.title}</h4>
                    {report.url ? <p className="report-url">{report.url}</p> : null}
                    {report.analyst_notes ? <p className="report-notes-preview">{report.analyst_notes}</p> : null}
                    <p>
                      {report.created_at
                        ? `Captured at ${new Date(report.created_at).toLocaleString()}`
                        : "Timestamp unavailable"}
                    </p>
                  </article>
                ))
              )}
            </div>

            <div className="case-workbench">
              <div className="panel-heading compact-heading">
                <div>
                  <p className="panel-kicker">Investigation Desk</p>
                  <h3>Case status and analyst notes</h3>
                </div>
              </div>

              {selectedReport ? (
                <>
                  <div className="case-workbench-summary">
                    <div className="report-topline">
                      <span className="report-tag">{selectedReport.type}</span>
                      <span className={`risk-badge risk-${selectedReport.risk_level ?? "low"}`}>
                        {selectedReport.risk_level ?? "low"} risk
                      </span>
                    </div>
                    <h4>{selectedReport.title}</h4>
                    <p className="case-meta-line">
                      <strong>Location:</strong> {prettyLocation(selectedReport.location)}
                    </p>
                    {selectedReport.url ? (
                      <p className="case-meta-line">
                        <strong>URL:</strong> {selectedReport.url}
                      </p>
                    ) : null}
                    <p className="case-meta-line">
                      <strong>Model:</strong> {prettyModel(selectedReport.model_used)}
                    </p>
                    <p className="case-meta-line">
                      <strong>AI reason:</strong> {selectedReport.ai_explanation ?? "No explanation available."}
                    </p>
                    {entityItems(relatedLinks?.entity_summary ?? selectedReport.entity_summary).length ? (
                      <div className="entity-block">
                        <strong className="entity-block-title">Evidence entities</strong>
                        <div className="entity-grid">
                          {entityItems(relatedLinks?.entity_summary ?? selectedReport.entity_summary).map((group) => (
                            <div key={group.label} className="entity-group">
                              <span className="entity-label">{group.label}</span>
                              <div className="entity-tags">
                                {group.values.map((value) => (
                                  <span key={`${group.label}-${value}`} className="entity-tag">
                                    {value}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>

                  <div className="form-grid">
                    <label>
                      <span>Case status</span>
                      <select value={caseStatus} onChange={(event) => setCaseStatus(event.target.value)}>
                        <option value="new">New</option>
                        <option value="under_review">Under Review</option>
                        <option value="confirmed_fraud">Confirmed Fraud</option>
                        <option value="false_positive">False Positive</option>
                        <option value="closed">Closed</option>
                      </select>
                    </label>
                    <label className="form-span-2">
                      <span>Analyst notes</span>
                      <textarea
                        rows={5}
                        placeholder="Add investigation notes, evidence summary, or resolution details"
                        value={caseNotes}
                        onChange={(event) => setCaseNotes(event.target.value)}
                      />
                    </label>
                  </div>

                  <button className="primary-button" onClick={() => void handleCaseUpdate()} disabled={caseSaving}>
                    {caseSaving ? "Saving case..." : "Save case update"}
                  </button>

                  <div className="related-cases-panel">
                    <div className="panel-heading compact-heading">
                      <div>
                        <p className="panel-kicker">Linked Cases</p>
                        <h3>Shared evidence across reports</h3>
                      </div>
                    </div>
                    {relatedLoading ? (
                      <p className="empty-state">Finding related cases...</p>
                    ) : !relatedLinks?.related_reports?.length ? (
                      <p className="empty-state">No linked reports found from the current evidence entities.</p>
                    ) : (
                      <div className="related-case-list">
                        {relatedLinks.related_reports.map((report) => (
                          <article
                            key={report.report_id ?? report.title}
                            className="related-case-card"
                            onClick={() => setSelectedReportId(report.report_id ?? "")}
                          >
                            <div className="report-topline">
                              <span className="report-tag">{report.type}</span>
                              <span className="case-status-badge">{prettyStatus(report.status)}</span>
                            </div>
                            <h4>{report.title}</h4>
                            <p className="case-meta-line">
                              <strong>Location:</strong> {prettyLocation(report.location)}
                            </p>
                            {Array.isArray(report.shared_evidence) && report.shared_evidence.length ? (
                              <p className="case-meta-line">
                                <strong>Shared evidence:</strong> {report.shared_evidence.join(", ")}
                              </p>
                            ) : null}
                          </article>
                        ))}
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <p className="empty-state">Select a report from the live feed to review and update its case details.</p>
              )}
            </div>
          </section>
        </section>
        )}
          <footer className="app-footer">
            <span>CyberFraud Intelligence</span>
            <span>Built for cybercrime reporting, chatbot triage, and geo analytics</span>
          </footer>
          </main>
        </div>
      </div>
    </div>
  );
}

export default App;
