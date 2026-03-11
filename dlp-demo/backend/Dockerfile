FROM python:3.10-slim
WORKDIR /app

# System deps: Tesseract OCR, Poppler (pdf2image), OpenCV runtime, git
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    poppler-utils \
    libgl1 \
    libglib2.0-0 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone Octopii (depth-1 to keep image small)
RUN git clone --depth 1 https://github.com/redhuntlabs/Octopii.git /opt/octopii

# Python packages (textract is mocked by octopii_runner.py; keras/tensorflow not needed)
RUN pip install --no-cache-dir \
    flask pypdf \
    numpy scipy scikit-image deskew \
    pdf2image pytesseract \
    opencv-python-headless \
    pillow imutils xmltodict \
    nltk bs4 requests geotext spacy

# Pre-download NLTK corpora required by Octopii's text_utils
RUN python -c "import nltk; [nltk.download(r) for r in ['punkt','punkt_tab','maxent_ne_chunker','maxent_ne_chunker_tab','stopwords','words','averaged_perceptron_tagger','averaged_perceptron_tagger_eng']]"

# Download spaCy language model
RUN python -m spacy download en_core_web_sm

COPY . .
CMD ["python", "main.py"]
