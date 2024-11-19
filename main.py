import subprocess
from pathlib import Path
from typing import List, Optional
from openai import OpenAI
import re
import sys

IGNORE_FILES = {
    'pyi_rth_inspect.txt', 'pyi_rth_multiprocessing.txt',
    'pyi_rth_pkgres.txt', 'pyi_rth_pkgutil.txt',
    'pyi_rth_setuptools.txt', 'pyiboot01_bootstrap.txt',
    'pyi_rth_cryptography_openssl.txt', 'pyi_rth_certifi.txt',
}


class MalwareAnalyzer:
    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)
        self.system_prompt = (
            "Check if the provided code is considered a virus or malware. "
            "If it is, return `True`; otherwise, return `False`. "
            "Don't describe anything. Return a boolean value: `True` or `False`."
        )

    def extract_stringData(self, file_path: str) -> List[str]:
        """리눅스 stringData 명령어로 문자열 추출"""
        result = subprocess.run(['strings', file_path],
                                capture_output=True, text=True, check=True)
        return result.stdout.splitlines()

    def decompile_python(self, file_path: str) -> List[str]:
        """https://github.com/pyinstxtractor/pyinstxtractor-go 를 빌드한 디컴파일러 사용"""
        subprocess.run(['./files/pyinstxtractor', file_path],
                       capture_output=True, text=False, check=True)

        extracted_path = Path(f'{file_path}_extracted')
        extracted_path = str(extracted_path).replace('files/', '')
        result = subprocess.run(f'ls {extracted_path} | grep .txt',
                                capture_output=True, text=True, shell=True, check=True)

        filenames = [
            fname.replace('.txt', '')
            for fname in result.stdout.splitlines()
            if fname not in IGNORE_FILES
        ]

        for filename in filenames:
            output_name = filename.replace(' ', '_')
            subprocess.run(
                f'pydec "{extracted_path}/{filename}.pyc" >> ./{output_name}.py',
                shell=True, check=True, capture_output=True, text=True
            )
            print(f"Decompiled {output_name}")

        return filenames

    def clear_string(self, string: str) -> str:
        """문자열정리 - 수정 필요"""
        cleaned_string = re.sub(r"[^a-zA-Z0-9./]", " ", string)
        result = " ".join(word for word in cleaned_string.split() if len(word) >= 7).replace("'',", "")
        return result

    def analyze_code(self, code: str) -> bool:
        """gpt로 분석"""
        response = self.client.chat.completions.create(
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": code}
            ],
            model="gpt-4o-mini"
        )
        return response.choices[0].message.content.lower() == 'true'


def main():
    analyzer = MalwareAnalyzer(
        "OPENAI_API_KEY"
    )

    file_path = sys.argv[1]

    stringData = analyzer.extract_stringData(file_path)
    combined_stringData = "\n".join(stringData)

    if 'python' in combined_stringData.lower():
        print("Python code detected. Analyzing...")
        decompiled_files = analyzer.decompile_python(file_path)

        for filename in decompiled_files:
            output_name = filename.replace(' ', '_')
            print(f"Analyzing {output_name}.py")

            with open(f'{output_name}.py', 'r') as f:
                is_malware = analyzer.analyze_code(f.read())
                print(f"Is malware: {is_malware}")
        file_path = str(file_path).replace('files/', '')
        subprocess.run(f'rm -r {file_path}_extracted', shell=True, check=True)
        for filename in decompiled_files:
            output_name = filename.replace(' ', '_')
            subprocess.run(f'rm {output_name}.py', shell=True, check=True)


    else:
        print("No Malware code detected.")

if __name__ == "__main__":
    main()
