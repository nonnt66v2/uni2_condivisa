#!/bin/bash

convert_pdfs() {
    local INPUT_DIR="$1"
    local OUTPUT_DIR="$2"

    echo "Conversione da '$INPUT_DIR' a '$OUTPUT_DIR'..."

    mkdir -p "$OUTPUT_DIR"

    if [ ! -d "$INPUT_DIR" ]; then
        echo "❌ La cartella '$INPUT_DIR' non esiste, salto..."
        return
    fi

    shopt -s nullglob
    local pdf_files=("$INPUT_DIR"/*.pdf)
    shopt -u nullglob

    if [ ${#pdf_files[@]} -eq 0 ]; then
        echo "⚠️  Nessun file PDF trovato in '$INPUT_DIR'."
        return
    fi

    for pdf in "${pdf_files[@]}"; do
        filename=$(basename "$pdf" .pdf)
        txtfile="$OUTPUT_DIR/$filename.txt"

        echo "📝 Converto: $pdf → $txtfile"
        pdftotext "$pdf" "$txtfile"
    done

    echo "✅ Conversione completata per '$INPUT_DIR'!"
    echo
}

convert_pdfs "slides" "slideTXT"
convert_pdfs "trascrizioni" "trascrizioniTXT"

echo "Tutte le conversioni sono state completate!"

