/* WanderWays front-end: every page loads its data from the JSON API. */
"use strict";

// NOTE(dev): the old mobile app still reads /api/v1/bookings (no login needed).
// Remove it once the v2 migration is finished - ticket WW-142.

async function api(path, options = {}) {
  const opts = { credentials: "same-origin", headers: {}, ...options };
  if (opts.body !== undefined && typeof opts.body !== "string") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, opts);
  const isJson = (res.headers.get("Content-Type") || "").includes("application/json");
  const data = isJson ? await res.json() : await res.text();
  if (!res.ok) {
    throw new Error((data && data.error) || `Request failed (HTTP ${res.status})`);
  }
  return data;
}

/* Small DOM helper: strings become text nodes, so API data is never parsed as HTML. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, value);
  }
  for (const child of children) {
    node.append(child instanceof Node ? child : document.createTextNode(String(child ?? "")));
  }
  return node;
}

const money = (v) =>
  "$" + Number(v).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

const badge = (status) => el("span", { class: `badge badge-${status}` }, status);

function showMessage(text, kind = "error") {
  const box = document.getElementById("page-message");
  if (!box) return;
  box.className = `message ${kind}`;
  box.textContent = text;
  box.hidden = false;
}

function formValues(form) {
  return Object.fromEntries(new FormData(form).entries());
}

const pages = {
  async login() {
    const form = document.getElementById("login-form");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await api("/api/auth/login", { method: "POST", body: formValues(form) });
        const next = new URLSearchParams(location.search).get("next");
        location.href = next && next.startsWith("/") && !next.startsWith("//") ? next : "/dashboard";
      } catch (err) {
        showMessage(err.message);
      }
    });
  },

  async dashboard() {
    const data = await api("/api/bookings");
    document.getElementById("booking-count").textContent = `${data.count} booking(s)`;
    const body = document.getElementById("bookings-body");
    body.replaceChildren();
    if (data.count === 0) {
      body.append(el("tr", {}, el("td", { colspan: 7, class: "muted" }, "No bookings yet.")));
      return;
    }
    for (const b of data.bookings) {
      body.append(
        el("tr", {},
          el("td", {}, el("a", { href: `/bookings/${b.id}` }, b.booking_ref)),
          el("td", {}, b.customer_name),
          el("td", {}, b.destination),
          el("td", {}, `${b.depart_date} → ${b.return_date}`),
          el("td", {}, b.travellers),
          el("td", {}, money(b.total_price)),
          el("td", {}, badge(b.status)),
        ),
      );
    }
  },

  async bookingDetail() {
    const id = document.body.dataset.bookingId;
    const form = document.getElementById("booking-edit-form");

    const render = (b) => {
      document.getElementById("booking-title").textContent = `Booking ${b.booking_ref}`;
      document.getElementById("booking-status").replaceChildren(badge(b.status));
      const rows = [
        ["Customer", b.customer_name],
        ["Agent", b.agent_name || "Not assigned"],
        ["Destination", b.destination],
        ["Hotel", b.hotel],
        ["Dates", `${b.depart_date} → ${b.return_date}`],
        ["Travellers", b.travellers],
        ["Total price", money(b.total_price)],
        ["Passport no.", b.passport_no],
        ["Card", `•••• ${b.payment_last4}`],
        ["Notes", b.notes || "-"],
      ];
      document.getElementById("booking-details").replaceChildren(
        ...rows.flatMap(([label, value]) => [el("dt", {}, label), el("dd", {}, value)]),
      );
      form.depart_date.value = b.depart_date;
      form.return_date.value = b.return_date;
      form.travellers.value = b.travellers;
      form.notes.value = b.notes;
    };

    render(await api(`/api/bookings/${id}`));

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const values = formValues(form);
      values.travellers = Number(values.travellers);
      try {
        render(await api(`/api/bookings/${id}`, { method: "PUT", body: values }));
        showMessage("Booking updated.", "success");
      } catch (err) {
        showMessage(err.message);
      }
    });

    document.getElementById("cancel-booking").addEventListener("click", async () => {
      if (!confirm("Cancel this booking?")) return;
      try {
        render(await api(`/api/bookings/${id}/cancel`, { method: "POST" }));
        showMessage("Booking cancelled.", "success");
      } catch (err) {
        showMessage(err.message);
      }
    });
  },

  async bookingNew() {
    const [destinations, agents] = await Promise.all([api("/api/destinations"), api("/api/agents")]);
    const destSelect = document.getElementById("destination");
    const hotelSelect = document.getElementById("hotel");
    const agentSelect = document.getElementById("agent");

    destSelect.replaceChildren(
      ...destinations.map((d) => el("option", { value: d.name }, `${d.name} - ${money(d.price_per_traveller)} pp`)),
    );
    const fillHotels = () => {
      const chosen = destinations.find((d) => d.name === destSelect.value);
      hotelSelect.replaceChildren(...chosen.hotels.map((h) => el("option", { value: h }, h)));
    };
    destSelect.addEventListener("change", fillHotels);
    fillHotels();
    agentSelect.append(...agents.map((a) => el("option", { value: a.id }, a.full_name)));

    const form = document.getElementById("booking-new-form");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const values = formValues(form);
      values.travellers = Number(values.travellers);
      values.agent_id = values.agent_id ? Number(values.agent_id) : null;
      try {
        const booking = await api("/api/bookings", { method: "POST", body: values });
        location.href = `/bookings/${booking.id}`;
      } catch (err) {
        showMessage(err.message);
      }
    });
  },

  async profile() {
    const id = document.body.dataset.userId;
    const form = document.getElementById("profile-form");
    const render = (u) => {
      document.getElementById("profile-username").textContent = u.username;
      document.getElementById("profile-role").textContent = u.role;
      form.full_name.value = u.full_name;
      form.email.value = u.email;
      form.phone.value = u.phone || "";
    };

    render(await api(`/api/users/${id}`));

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        render(await api(`/api/users/${id}`, { method: "PATCH", body: formValues(form) }));
        showMessage("Profile saved.", "success");
      } catch (err) {
        showMessage(err.message);
      }
    });
  },

  async admin() {
    const statsBox = document.getElementById("stats");
    try {
      const s = await api("/api/admin/stats");
      const tiles = [
        ["Total bookings", s.total_bookings],
        ["Confirmed", s.bookings_by_status.confirmed || 0],
        ["Pending", s.bookings_by_status.pending || 0],
        ["Cancelled", s.bookings_by_status.cancelled || 0],
        ["Confirmed revenue", money(s.confirmed_revenue_usd)],
      ];
      statsBox.replaceChildren(
        ...tiles.map(([label, value]) => el("div", { class: "stat" }, el("div", { class: "label" }, label), el("div", { class: "value" }, value))),
      );
    } catch (err) {
      statsBox.replaceChildren(el("p", { class: "muted" }, `Statistics unavailable: ${err.message}`));
    }

    const data = await api("/api/admin/users");
    document.getElementById("users-body").replaceChildren(
      ...data.users.map((u) =>
        el("tr", {},
          el("td", {}, u.id),
          el("td", {}, u.username),
          el("td", {}, u.full_name),
          el("td", {}, u.email),
          el("td", {}, u.phone || "-"),
          el("td", {}, el("span", { class: `role role-${u.role}` }, u.role)),
        ),
      ),
    );
  },
};

document.addEventListener("DOMContentLoaded", () => {
  const logout = document.getElementById("logout-link");
  if (logout) {
    logout.addEventListener("click", async (event) => {
      event.preventDefault();
      try {
        await api("/api/auth/logout", { method: "POST" });
      } finally {
        location.href = "/login";
      }
    });
  }

  const page = pages[document.body.dataset.page];
  if (page) {
    page().catch((err) => showMessage(err.message));
  }
});
