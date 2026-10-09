import { useRef, useState, type ChangeEvent, type DragEvent, type KeyboardEvent, type MouseEvent } from 'react';
import { formatBytes } from '../../lib/format';

interface LogDropzoneProps {
  onFile: (file: File) => void;
  disabled?: boolean;
  onDemo?: () => void;
}

const MAX_FILE_SIZE = 200 * 1024 * 1024;
const LOG_NAME_PATTERN = /\.(log|txt)(\.\d+)?$|access|error/i;

export function LogDropzone({ onFile, disabled = false, onDemo }: LogDropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [chosenFile, setChosenFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  function openPicker() {
    if (!disabled) inputRef.current?.click();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (disabled || (event.key !== 'Enter' && event.key !== ' ')) return;
    event.preventDefault();
    openPicker();
  }

  function validateAndPassFile(file: File) {
    setError(null);
    setWarning(null);
    setNotice(null);

    if (file.name.toLowerCase().endsWith('.gz')) {
      setChosenFile(null);
      setError('.gz not supported yet');
      return;
    }
    if (file.size === 0) {
      setChosenFile(null);
      setError('File is empty.');
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setChosenFile(null);
      setError('File too large for in-browser analysis (max 200 MB)');
      return;
    }

    setChosenFile(file);
    if (!LOG_NAME_PATTERN.test(file.name)) {
      setWarning('This file name does not look like a log file.');
    }
    onFile(file);
  }

  function handleFiles(files: FileList | null) {
    if (disabled || !files || files.length === 0) return;
    const hasMultipleFiles = files.length > 1;
    validateAndPassFile(files[0]);
    if (hasMultipleFiles) setNotice('Only the first file was selected.');
  }

  function handleInputChange(event: ChangeEvent<HTMLInputElement>) {
    handleFiles(event.currentTarget.files);
    event.currentTarget.value = '';
  }

  function handleDragOver(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    if (!disabled) setDragActive(true);
  }

  function handleDragLeave(event: DragEvent<HTMLDivElement>) {
    if (event.currentTarget.contains(event.relatedTarget as Node | null)) return;
    setDragActive(false);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragActive(false);
    handleFiles(event.dataTransfer.files);
  }

  function handleClick(event: MouseEvent<HTMLDivElement>) {
    if (event.target === inputRef.current) return;
    openPicker();
  }

  const boxClassName = [
    'cursor-pointer rounded-lg border-2 border-dashed p-8 text-center outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
    dragActive ? 'border-cyan-500 bg-cyan-50' : 'border-slate-300',
    disabled ? 'cursor-not-allowed opacity-60' : '',
  ].filter(Boolean).join(' ');

  return (
    <div className="space-y-3">
      <div
        aria-label="Choose or drop one log file"
        aria-disabled={disabled}
        className={boxClassName}
        onClick={handleClick}
        onDragEnter={handleDragOver}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onKeyDown={handleKeyDown}
        role="button"
        tabIndex={disabled ? -1 : 0}
      >
        <input
          accept=".log,.txt,text/plain,.gz"
          aria-hidden="true"
          className="hidden"
          onChange={handleInputChange}
          ref={inputRef}
          tabIndex={-1}
          type="file"
        />
        <p className="font-medium">Drop one log file here, or click to browse</p>
        <p className="mt-1 text-sm text-slate-600">.log, .txt, or .gz</p>
        {chosenFile && (
          <p className="mt-3 text-sm" aria-live="polite">
            {chosenFile.name} ({formatBytes(chosenFile.size)})
          </p>
        )}
      </div>

      <p className="text-sm text-slate-600">Parsed locally in your browser. 0 KB sent to any server.</p>
      {notice && <p className="text-sm text-slate-600" role="status">{notice}</p>}
      {warning && <p className="text-sm text-amber-700" role="status">{warning}</p>}
      {error && <p className="text-sm text-red-600" role="alert">{error}</p>}

      <button
        className="rounded-md border border-slate-300 px-4 py-2 text-sm hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
        disabled={disabled || !onDemo}
        onClick={onDemo}
        type="button"
      >
        Try demo log
      </button>
    </div>
  );
}
