// ------------------------- GAUGE DRAW -------------------------
function drawGauge(elem, pct) {
    const r = 70;
    const c = 2 * Math.PI * r;

    const svg = `
    <svg viewBox="0 0 180 180">
        <defs>
            <linearGradient id="g1" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stop-color="#7c5cff"/>
                <stop offset="100%" stop-color="#5aa8ff"/>
            </linearGradient>
        </defs>

        <circle cx="90" cy="90" r="${r}"
            stroke="rgba(255,255,255,0.08)"
            stroke-width="16"
            fill="none"
        />

        <circle cx="90" cy="90" r="${r}"
            stroke="url(#g1)"
            stroke-width="16"
            stroke-dasharray="${c}"
            stroke-dashoffset="${c * (1 - pct / 100)}"
            stroke-linecap="round"
            fill="none"
        />
    </svg>`;

    elem.innerHTML = svg;

    const val = document.getElementById("gauge_val");
    if (val) val.innerText = Math.round(pct) + "%";
}

// ------------------------- SAFETY LINE CHART -------------------------
function drawSafetyChart(labels, values) {
    const canvas = document.getElementById("safetyChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");

    if (window._safetyChart) window._safetyChart.destroy();

    window._safetyChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label: "Safety Score",
                data: values,
                tension: 0.3,
                fill: true,
                backgroundColor: "rgba(122, 92, 255, 0.12)",
                borderColor: "#7c5cff",
                pointRadius: 3
            }]
        },
        options: {
            scales: { y: { min: 0, max: 100 } },
            plugins: { legend: { display: false } },
            animation: { duration: 600 }
        }
    });
}

// ------------------------- HISTORY RENDER -------------------------
function populateHistory(hist) {
    const el = document.getElementById("historyList");
    if (!el) return;
    el.innerHTML = "";
    hist.slice().reverse().forEach(r => {
        const row = document.createElement("div");
        row.className = "history-row";
        row.innerHTML = `
            <div style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                ${r.timestamp} • ${r.url}
            </div>
            <div style="min-width:110px; text-align:right;">
                ${r.prediction.toUpperCase()} • ${Math.round(r.safety_score)}%
            </div>
        `;
        el.appendChild(row);
    });
}

// ------------------------- AJAX FORM SUBMIT -------------------------
document.addEventListener("DOMContentLoaded", function () {
    // Render initial chart + history
    const safety_series = window.SAFETY_DATA || [];
    const labels = safety_series.map(x => new Date(x.timestamp).toLocaleTimeString());
    const values = safety_series.map(x => Number(x.safety_score) || 0);
    drawSafetyChart(labels, values);

    const history_series = window.HISTORY_DATA || [];
    populateHistory(history_series);

    // Initial gauge
    const lastSafety = values.length ? values[values.length - 1] : 50;
    drawGauge(document.getElementById("gauge"), lastSafety);

    // Form submit
    const form = document.getElementById("scanForm");
    form.addEventListener("submit", (e) => {
        e.preventDefault();

        const url = document.getElementById("urlInput").value.trim();
        if (!url) return;

        const resultBox = document.getElementById("resultBox");
        resultBox.style.display = "block";
        resultBox.innerText = "Scanning...";
        document.getElementById("timeBox").innerText = new Date().toLocaleString();

        fetch("/api/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                resultBox.innerText = "Error: " + data.error;
                return;
            }

            const pred = data.prediction;
            const prob = data.prob_phishing;
            const safety = data.safety_score;

            resultBox.className = "result " + (pred === "legit" ? "safe" : "danger");
            resultBox.innerHTML = `
                <div style="font-size:15px;">Result: <b>${pred.toUpperCase()}</b></div>
                <div style="font-size:13px; margin-top:6px;">Confidence (phishing): ${(prob * 100).toFixed(1)}%</div>
                <div style="font-size:13px;">Safety Score: ${Math.round(safety)}%</div>
            `;
            document.getElementById("probBox").innerText = `Phish Prob: ${(prob * 100).toFixed(2)}%`;
            document.getElementById("timeBox").innerText = new Date().toLocaleString();
            drawGauge(document.getElementById("gauge"), safety);
        })
        .catch(err => {
            resultBox.innerText = "Server error";
            console.error(err);
        });
    });
});

    document.addEventListener('DOMContentLoaded', function() {
        var flashMessages = document.querySelectorAll('.flashes li');
        
        if (flashMessages.length > 0) {
            flashMessages.forEach(function(message, index) {
                // 1. Initial appearance (slide in)
                setTimeout(function() {
                    message.classList.add('show-flash');
                }, 100 + (index * 100)); 

                // 2. Hide (slide out) after 2 seconds
                const DISPLAY_TIME = 2000; 
                
                setTimeout(function() {
                    // Start the hide transition
                    message.classList.remove('show-flash');
                    message.classList.add('hide-flash');
                    
                    // Remove the element completely after the transition is done
                    setTimeout(function() {
                        message.remove();
                        var container = document.querySelector('.flashes');
                        if (container && container.children.length === 0) {
                            container.remove();
                        }
                    }, 400); 
                }, DISPLAY_TIME + (index * 100)); 
            });
        }
    });


    