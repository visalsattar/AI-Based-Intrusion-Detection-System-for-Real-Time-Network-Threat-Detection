# 📁 AI-Based IDS — Full Project Directory

```
AI-Based-Intrusion-Detection-System-for-Real-Time-Network-Threat-Detection/
│
├── 🔧 Root Configuration
│   ├── .dockerignore
│   ├── .env
│   ├── .env.example
│   ├── .gitignore
│   ├── docker-compose.yml              # Multi-container orchestration (backend + frontend + Redis)
│   ├── LICENSE
│   ├── package.json
│   ├── package-lock.json
│   ├── README.md                       # Project documentation
│   ├── simulate_attack.py              # Attack simulation script
│   ├── start-capture.ps1               # PowerShell capture launcher
│   ├── DEMO_THREAT_CAPTURE.txt         # Demo instructions
│   └── AI_IDS_Project_Guide_and_Honest_Audit.docx
│
├── .github/
│   ├── modernize/code-migration/
│   │   └── .gitignore
│   └── workflows/
│       └── backend-tests.yml           # CI pipeline for backend tests
│
├── .vscode/
│   └── settings.json
│
├── 🧪 scripts/                       # Windows helper scripts
│   ├── 1-install-dev-dependencies.bat
│   ├── 2-start-docker.bat
│   ├── 3-start-backend.bat
│   ├── 4-start-frontend.bat
│   └── 5-demo-threat-capture.bat
│
│
├── ⚙️ backend/
│   ├── .env
│   ├── .env.example
│   ├── Dockerfile                      # Backend container image
│   ├── requirements.txt                # Python dependencies
│   ├── README.md                       # Backend documentation
│   ├── main.py                         # Entry point (Flask + SocketIO + IDS modes)
│   ├── routes.py                       # REST API endpoints
│   ├── run_training.py                 # Standalone model training script
│   ├── verify_ensemble.py              # AE+RF ensemble verification
│   ├── validate_live_capture.py        # Live capture validation tool
│   ├── skew_report.py                  # Feature skew analysis
│   │
│   ├── config/
│   │   ├── config.yml                  # App configuration
│   │   ├── logging_config.py           # Logging setup
│   │   ├── GeoLite2-City.mmdb          # MaxMind GeoIP database
│   │   ├── whitelist.json              # IP whitelist (active)
│   │   └── whitelist.example.json      # Whitelist template
│   │
│   ├── data/
│   │   ├── CICIDS2017/
│   │   │   └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv   # Raw CICIDS2017 dataset
│   │   ├── preprocessed/
│   │   │   ├── CICIDS2017_cleaned.csv  # Cleaned + normalized dataset
│   │   │   ├── CICIDS2017_train.csv    # Training split
│   │   │   ├── CICIDS2017_test.csv     # Test split
│   │   │   ├── UNSW-NB15_train.csv     # UNSW-NB15 dataset
│   │   │   ├── X_test_flat.npy         # Flat test features
│   │   │   └── y_test_flat.npy         # Flat test labels
│   │   ├── UNSW-NB15/
│   │   │   └── NUSW-NB15_features.csv  # UNSW-NB15 feature definitions
│   │   └── rescale_dataset.py          # Dataset rescaling utility
│   │
│   ├── models/
│   │   ├── autoencoder.h5              # Trained autoencoder (unsupervised)
│   │   ├── cnn_classifier.h5           # CNN classifier (offline evaluation only)
│   │   ├── random_forest.pkl           # Random Forest (supervised binary)
│   │   ├── feature_scaler.pkl          # MinMaxScaler (fitted on training data)
│   │   ├── label_map.json              # Class label mapping {"0":"Benign","1":"DDoS"}
│   │   └── real_metrics.json           # Calibrated AE threshold + eval metrics
│   │
│   ├── src/                            # Core source modules
│   │   ├── __init__.py
│   │   ├── ids_pipeline.py             # ★ MAIN: Real-time capture → features → AI → alerts
│   │   ├── data_preprocessing.py       # CICIDS2017 preprocessing + MinMaxScaler
│   │   ├── ai_model_development.py     # Hybrid CNN-Autoencoder + RF training
│   │   ├── model_evaluation.py         # Model evaluation + threshold calibration
│   │   ├── model_optimization.py       # Hyperparameter optimization
│   │   ├── sequence_builder.py         # Temporal sequence builder (for CNN)
│   │   ├── dataset_specific_handling.py # Dataset-specific preprocessing
│   │   ├── geo_utils.py                # GeoIP resolution for threat map
│   │   ├── network_utils.py            # Network interface detection
│   │   ├── redis_util.py               # Redis connection factory
│   │   ├── redis_alert_bridge.py       # Redis → SocketIO alert bridge
│   │   ├── threat_evidence.py          # Threat evidence capture + persistence
│   │   ├── threat_intel_service.py     # Threat intelligence API integration
│   │   ├── calibrate_override.py       # Override threshold calibration
│   │   └── system_status.py            # System health/status reporting
│   │
│   ├── tests/                          # Backend test suite
│   │   ├── conftest.py                 # Pytest fixtures
│   │   ├── stubs.py                    # Test stubs/mocks
│   │   ├── feature_order.py            # Feature ordering verification
│   │   ├── test_ids_pipeline_feature_parity.py  # ★ CICFlowMeter feature parity tests
│   │   ├── test_feature_alignment.py   # Feature alignment tests
│   │   ├── test_flow_scoring.py        # Flow scoring tests
│   │   ├── test_inference.py           # Inference pipeline tests
│   │   ├── test_model_training.py      # Training pipeline tests
│   │   ├── test_preprocessing.py       # Preprocessing tests
│   │   ├── test_preprocessing_extra.py # Extended preprocessing tests
│   │   ├── test_network_utils.py       # Network utility tests
│   │   ├── test_whitelist.py           # IP whitelist tests
│   │   ├── test_routes_security.py     # API security tests
│   │   ├── test_skew_report.py         # Skew report tests
│   │   ├── test_threat_intel_service.py# Threat intel tests
│   │   ├── test_verify_ensemble.py     # Ensemble verification tests
│   │   └── test_proposed_block_queue.py# IPS block queue tests
│   │
│   ├── evidence/                       # Captured threat evidence
│   │   ├── alerts.jsonl                # Alert log (JSON Lines)
│   │   ├── live_lab_features.csv       # Live capture feature dump
│   │   └── threat-*.png                # Threat evidence screenshots
│   │
│   ├── logs/
│   │   └── model_disagreements.csv     # AE/RF disagreement dump
│   │
│   └── docs/
│       └── CHANGES.md                  # Backend changelog
│
│
├── 🌐 frontend/
│   ├── .env
│   ├── .env.example
│   ├── Dockerfile                      # Frontend container image
│   ├── package.json                    # Node.js dependencies
│   ├── package-lock.json
│   ├── README.md                       # Frontend documentation
│   │
│   ├── public/
│   │   ├── index.html                  # HTML entry point
│   │   ├── favicon.ico
│   │   ├── logo192.png
│   │   ├── logo512.png
│   │   ├── manifest.json
│   │   ├── robots.txt
│   │   ├── critical.mp3                # Critical alert sound
│   │   └── high.mp3                    # High alert sound
│   │
│   └── src/
│       ├── App.css                     # Global app styles
│       ├── App.jsx                     # React app root + routing
│       ├── index.js                    # React entry point
│       │
│       ├── components/
│       │   ├── AlertTable.jsx          # Real-time alert table
│       │   ├── Charts.jsx             # Chart components
│       │   ├── MetricCard.jsx         # Dashboard metric cards
│       │   ├── Navbar.jsx             # Navigation bar
│       │   └── TrafficCharts.jsx      # Network traffic visualizations
│       │
│       ├── pages/
│       │   ├── Dashboard.jsx           # Main dashboard page
│       │   ├── History.jsx             # Alert history page
│       │   ├── Settings.jsx            # Settings page (thresholds, IPS toggle)
│       │   └── ThreatIntel.jsx         # Threat intelligence + GeoIP map
│       │
│       └── styles/
│           ├── Dashboard.css
│           ├── global.css
│           ├── Navbar.css
│           └── Pages.css
│
│
└── 📄 Thesis/
    ├── 2_THESIS/
    │   ├── BACKUP/FYP-II(Backup).docx
    │   ├── FINAL/FYP-II.docx           # Final thesis document
    │   └── txt/                         # Plaintext exports
    │       ├── AI-Based Intrusion Detection System - Project Overview.txt
    │       ├── backkend.txt
    │       ├── frontend.txt
    │       ├── root.txt
    │       └── README.md
    ├── 3_PROPOSALS/
    │   ├── FYP-I/FYP-I Proposal.docx
    │   └── FYP-II/FYP-II Proposal.docx
    ├── 4_PRESENTATION/
    │   ├── FYP-I Presentation.pptx
    │   └── FYP-II Presentation.pptx
    ├── 5_RESEARCH/
    │   ├── AI_IDS_Mapping.docx
    │   ├── AI-IDS_Current_Implementation_Summary_and_Viva_QA.docx
    │   ├── AI-IDS_Current_Implementation_Summary_and_Viva_QA.txt
    │   ├── FYP-I Research Summary.docx
    │   ├── FYP-II Research Summary.docx
    │   └── Research_Proposal.docx
    ├── AI_IDS_Project_Guide_and_Honest_Audit.docx
    ├── AI-BASED_INTRUSION_DETECTION_SYSTEM_...FYP-II.docx
    ├── AI-BASED_INTRUSION_DETECTION_SYSTEM_...FYP-II(Backup).docx
    ├── AI-Based-...-1.0-models.tar.gz      # Pre-trained model archive
    ├── AI-Based-...-1.0-models.zip
    ├── 20260923-2105-30.mp4                 # Demo recordings
    └── 20260923-2213-40.mp4
```

## Quick Stats

| Category | Files | Key Entry Point |
|----------|-------|----------------|
| **Backend (Python)** | ~45 source + test files | `backend/main.py` |
| **Frontend (React)** | ~15 source files | `frontend/src/App.jsx` |
| **ML Models** | 5 artifacts | `backend/models/` |
| **Datasets** | 5 data files | `backend/data/` |
| **Tests** | 15 test files | `backend/tests/` |
| **Thesis/Docs** | ~20 documents | `Thesis/` |
| **DevOps** | Docker + CI + bat scripts | `docker-compose.yml` |
