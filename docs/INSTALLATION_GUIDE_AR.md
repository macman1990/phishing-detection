# دليل تثبيت وتشغيل PhishGuard

## قبل البدء

المشروع تطبيق Python/Streamlit. بيئة المراجعة المتاحة استخدمت Python 3.11.3؛ لا يوجد ملف يعلن نطاقًا رسميًا لبقية الإصدارات، لذلك يوصى بـ Python 3.11. يلزم Git و`pip`. لا يلزم إعداد قاعدة بيانات؛ لا يستخدم الكود SQLite.

**تحذير شبكة وخصوصية:** تحليل البريد يرسل الروابط لخدمات خارجية، كما يتبع analyzer أول رابط في الرسالة بطلب HTTP. فحص URL يرسل الرابط لأربعة مصادر تهديد. استخدم بيئة اختبار معزولة وروابط/رسائل مصرحًا بها، ولا تدخل روابط داخلية أو رسائل سرية. التطبيق لا يفرض العزل نيابة عنك.

## 1. التثبيت على Windows

افتح PowerShell ونفذ:

```powershell
git clone https://github.com/macman1990/phishing-detection.git
Set-Location phishing-detection
py -3.11 -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

استخدم رابط المستودع المناسب إن كنت تعمل على fork أو نسخة خاصة. لا تُحذف البيئة `venv/` الحالية تلقائيًا؛ إنشاء بيئة جديدة لا يحتاج حذف أي ملفات أخرى.

يمكن تفعيل البيئة اختياريًا:

```powershell
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

إذا كانت سياسة PowerShell تمنع التفعيل، لا تغيّر سياسة النظام؛ استخدم مسار `.\venv\Scripts\python.exe` المباشر كما في الأوامر السابقة.

## 2. أنظمة macOS وLinux

بعد تثبيت Python 3.11 وGit:

```bash
git clone https://github.com/macman1990/phishing-detection.git
cd phishing-detection
python3.11 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -r requirements.txt
```

تُستخدم `./venv/bin/streamlit run main.py` للتشغيل على هذه الأنظمة. قد تختلف أوامر تثبيت Python حسب مدير الحزم المستخدم.

## 3. إعداد ملف البيئة

أنشئ `.env` في جذر المشروع باستخدام محرر محلي، ولا تضعه في Git:

```dotenv
VIRUSTOTAL_API_KEY=ضع_مفتاحك_المحلي_هنا
GOOGLE_API_KEY=ضع_المفتاح_اختياريًا_هنا
SIEM_HOST=localhost
SIEM_PORT=514
```

- مفتاح VirusTotal مطلوب للحصول على نتيجة مفيدة من هذا المصدر.
- مفتاح Google Safe Browsing اختياري؛ من دونه تكون نتيجة المصدر `Unknown`.
- URLhaus وPhishTank يُستدعيان دون مفتاح وفق الكود الحالي.
- إذا لم يكن لديك SIEM، اترك الوجهة الافتراضية؛ يحاول التطبيق UDP إلى `localhost:514` ويستمر في حفظ السجل المحلي.
- لا تُرسل المفاتيح في محادثات أو تقارير أو screenshots. إذا انكشف مفتاح حقيقي، أبطله/دوّره من مزود الخدمة.

إعداد WHOIS اختياري وغير موجود في `requirements.txt`. لتفعيل فحص عمر النطاق فقط:

```powershell
.\venv\Scripts\python.exe -m pip install python-whois
```

بدون الحزمة يبقى بقية التحليل متاحًا لكن نتيجة WHOIS غير متوفرة.

## 4. التحقق من التثبيت

تحقق من نسخة Python والحزم الأساسية:

```powershell
.\venv\Scripts\python.exe --version
.\venv\Scripts\python.exe -c "import streamlit, plotly, pandas, numpy, sklearn, eml_parser, requests, reportlab; print('Core imports OK')"
```

هذا الاختبار لا يرسل طلبات إلى APIs ولا يشغل عينة بريد. لم أعد تثبيت الاعتماديات أثناء إعداد هذا الدليل؛ ملف `requirements.txt` الأصلي يحتوي إصدارات مثبتة كثيرة، وبعضها اعتماديات غير مباشرة.

## 5. تشغيل الواجهة

من جذر المشروع:

```powershell
.\venv\Scripts\streamlit.exe run main.py
```

يفتح Streamlit عادة `http://localhost:8501`. أوقف الخادم بـ `Ctrl+C` في نافذة الطرفية، وأعد التشغيل بالأمر نفسه. منفذ 8501 مضبوط في `.streamlit/config.toml`؛ إذا كان مستخدمًا، يمكن تحديد منفذ آخر في سطر التشغيل مثل `--server.port 8502`.

## 6. الاستخدام الأول

1. افتح تبويب **Email Analysis** لرفع ملف EML مصرح به.
2. اقرأ النتيجة والـ flags، ولا تعامل أي درجة على أنها حسم آلي.
3. راجع تبويب **Alerts History**؛ التنبيهات تُكتب محليًا في `reports/siem_alerts.log`.
4. أنشئ PDF من زر **Download Incident Report** عند الحاجة. الملف الافتراضي `reports/incident_report.pdf`.
5. تبويب **URL Checker** يتصل بخدمات VirusTotal وURLhaus وPhishTank وGoogle Safe Browsing. لا تستخدم رابطًا خاصًا أو يحمل token.
6. تبويب **Validation** يقرأ لقطة `reports/validation_report.json` الموجودة، ولا يعيد التدريب تلقائيًا.

### تجربة محلية لا تتصل بالإنترنت

يمكن اختبار قواعد URL فقط:

```powershell
.\venv\Scripts\python.exe -c "from modules.url_analyzer import analyze_url; print(analyze_url('https://example.com'))"
```

## 7. النموذج والتحقق

النموذج `data/model.pkl` غير متعقب في Git. إذا غاب وقت التنبؤ، يحاول التطبيق تدريبه من `data/dataset.csv`. لإنشاء النموذج يدويًا دون تشغيل تحليل بريد:

```powershell
.\venv\Scripts\python.exe -c "from modules.ml_classifier import train_model; train_model()"
```

بعد وجود النموذج يمكن تشغيل:

```powershell
.\venv\Scripts\python.exe data\validation.py
```

**تنبيه:** هذا السكريبت يكتب فوق الملف المتعقب `reports/validation_report.json`. انسخ الملف الحالي أولًا إذا كنت تريد الاحتفاظ بالنتائج المخزنة. السكريبت يقيّم النموذج ولا يمثل unit tests.

## 8. أدوات البيانات

لا تشغّل هذه الأدوات كجزء من التثبيت العادي:

- `data/download_dataset.py` يتصل بمصدر GitHub، يكتب `data/phishing_raw.csv`، ثم يعيد كتابة `data/dataset.csv`.
- `data/expand_dataset.py` ينزل مصادر خارجية، وقد يكتب ملفات جديدة ويستبدل `data/dataset.csv`.
- `data/create_dataset.py` يكتب مجموعة صغيرة اصطناعية فوق `data/dataset.csv`.

راجع المصدر وخذ نسخة احتياطية من الملفات قبل تشغيل أي منها. تشغيل هذه السكريبتات قد يغير نتائج التدريب الموجودة.

## 9. أمثلة CLI

تحليل EML متاح عبر:

```powershell
.\venv\Scripts\python.exe -m modules.risk_engine path\to\authorized-sample.eml
```

هذا المسار ليس offline: قد يرسل URL إلى خدمات خارجية ويتبع redirect. استخدم عينة مصرحًا بها فقط وفي شبكة مختبر مضبوطة. لا تستخدم الأمر على `data/test.eml` إلا بعد قبول اتصالاته الخارجية.

إنشاء PDF من CLI:

```powershell
.\venv\Scripts\python.exe -m modules.report_generator path\to\authorized-sample.eml
```

هذا الأمر يستدعي تحليل البريد نفسه، وبالتالي له المخاطر الشبكية ذاتها.

## 10. الملفات المحلية المهمة وعدم رفعها

- `.env`: أسرار وإعدادات محلية، مستثنى من Git.
- `data/model.pkl`: نموذج pickle محلي، مستثنى من Git؛ لا تحمّل pickle مجهول المصدر.
- `data/phishing_raw.csv`: بيانات خام محلية، مستثناة.
- `data/phishing_extra.csv`: مخرج تنزيل محتمل، مستثنى.
- `reports/siem_alerts.log`: قد يحوي بيانات المرسل والموضوع والروابط، مستثنى.
- `reports/incident_report.pdf`: تقرير محلي مولد، مستثنى.
- `venv/` أو `.venv/` و`__pycache__/`: بيئة وكاش محليان.

تظل `data/dataset.csv` و`data/phishing_full.csv` و`reports/validation_report.json` متعقبة حاليًا؛ راجع شروط مصدر البيانات والخصوصية قبل نشرها.

## 11. أخطاء شائعة

| المشكلة | الإجراء |
|---|---|
| `ModuleNotFoundError` لحزمة أساسية | تحقق من البيئة النشطة ثم نفّذ `python -m pip install -r requirements.txt` داخلها. |
| `python-whois` غير موجود | الحزمة اختيارية؛ ثبتها فقط إذا كنت تحتاج WHOIS. |
| نموذج مفقود | درّبه بالأمر الموضح أعلاه؛ تأكد من وجود `data/dataset.csv`. |
| التحقق يفشل بسبب ملف نموذج | أنشئ `data/model.pkl` أولًا. |
| VirusTotal يعيد 401/خطأ | راجع إعداد مفتاحك وحدود الاستخدام. لا تفسر النتيجة كأن الرابط نظيف. |
| Google Safe Browsing يعرض Unknown | المفتاح غير مهيأ أو فشل الطلب؛ افحص الإعدادات والاتصال. |
| الواجهة لا تبدأ بسبب المنفذ | استخدم `--server.port 8502` أو منفذًا متاحًا. |
| التنبيه لا يصل إلى SIEM | افحص `SIEM_HOST` و`SIEM_PORT` والـ listener. UDP لا يقدم تأكيد استلام. |
| سجل التنبيهات فارغ أو غير كامل | تحقق من `reports/siem_alerts.log`؛ الأسطر غير الصالحة يتجاهلها القارئ. |

## 12. حدود التحقق

لم يُشغّل تثبيت جديد أو اتصالات APIs أو تطبيق Streamlit كجزء من هذا الدليل. جميع أوامر التثبيت والتشغيل مبنية على ملفات المشروع والكود، لكن يجب تنفيذها في بيئة المختبر قبل العرض النهائي. لم تُتحقق خارجيًا من صلاحية مفاتيح API أو استقبال UDP.
