"""
Скрипт анализирует логи Suricata и получает данные об уязвимостях из Vulners API,
выявляет угрозы, имитирует реагирование и формирует отчет с визуализацией.
"""

import json
import csv
from datetime import datetime
from collections import Counter
import requests
import pandas as pd
import matplotlib.pyplot as plt
import os
import time


class SecurityMonitor:
    """Класс для мониторинга и анализа угроз безопасности"""
    
    def __init__(self, log_file_path, api_key):
        """
        Инициализация монитора
        
        Args:
            log_file_path (str): Путь к файлу с логами Suricata
            api_key (str): API ключ для Vulners
        """
        self.log_file_path = log_file_path
        self.api_key = api_key
        self.alerts = []
        self.threats = []
        self.blocked_ips = set()
        self.vulnerabilities = []
        
    def load_logs(self):
        """Загрузка и парсинг логов Suricata из JSON-файла"""
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as file:
                self.alerts = json.load(file)
            print(f"✅ Загружено {len(self.alerts)} записей из логов")
            return True
        except FileNotFoundError:
            print(f"❌ Файл {self.log_file_path} не найден")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ Ошибка парсинга JSON: {e}")
            return False
    
    def analyze_logs(self):
        """
        Анализ логов на предмет угроз
        
        Returns:
            dict: Статистика по угрозам
        """
        if not self.alerts:
            print("❌ Нет данных для анализа")
            return {}
        
        # Счетчики для статистики
        ip_counter = Counter()
        signature_counter = Counter()
        severity_counter = Counter()
        port_counter = Counter()
        
        threats_found = []
        
        for alert in self.alerts:
            src_ip = alert.get('src_ip', 'unknown')
            dest_port = alert.get('dest_port', 0)
            alert_data = alert.get('alert', {})
            signature = alert_data.get('signature', 'unknown')
            severity = alert_data.get('severity', 3)
            category = alert_data.get('category', 'unknown')
            
            # Собираем статистику
            ip_counter[src_ip] += 1
            signature_counter[signature] += 1
            severity_counter[severity] += 1
            if dest_port:
                port_counter[dest_port] += 1
            
            # Определяем угрозы
            threat = {
                'timestamp': alert.get('timestamp', ''),
                'src_ip': src_ip,
                'dest_port': dest_port,
                'signature': signature,
                'severity': severity,
                'category': category,
                'action': alert_data.get('action', 'allowed')
            }
            threats_found.append(threat)
        
        self.threats = threats_found
        
        # Сохраняем статистику
        self.stats = {
            'total_alerts': len(self.alerts),
            'unique_sources': len(ip_counter),
            'top_ips': ip_counter.most_common(10),
            'top_signatures': signature_counter.most_common(10),
            'severity_distribution': dict(severity_counter),
            'top_ports': port_counter.most_common(10)
        }
        
        print(f"\n📊 Статистика анализа:")
        print(f"   Всего оповещений: {self.stats['total_alerts']}")
        print(f"   Уникальных источников: {self.stats['unique_sources']}")
        print(f"   Распределение по severity: {self.stats['severity_distribution']}")
        
        return self.stats
    
    def get_vulners_data(self):
        """
        Получение данных об уязвимостях из Vulners API с использованием API ключа
        Запрашиваем последние критические уязвимости (CVSS >= 7.0)
        """
        print("\n🌐 Запрос данных из Vulners API...")
        
        # Vulners API endpoint для поиска с API ключом
        url = "https://vulners.com/api/v3/search/lucene/"
        
        # Формируем заголовки с API ключом
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': self.api_key
        }
        
        # Запрос последних критических уязвимостей
        payload = {
            "query": "cvss.score:[7.0 TO 10.0]",
            "size": 20,
            "sort": "published"
        }
        
        print(f"   Отправка запроса с API ключом: {self.api_key[:10]}...")
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=15)
            print(f"   Статус ответа: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   Получен ответ от API")
                
                # Проверяем структуру ответа
                if 'data' in data and 'search' in data['data']:
                    search_results = data['data']['search']
                    print(f"   Найдено результатов: {len(search_results)}")
                    
                    for item in search_results:
                        if isinstance(item, dict):
                            # Извлекаем ID уязвимости
                            vuln_id = item.get('id')
                            
                            if vuln_id:
                                # Пробуем получить детали через другой эндпоинт
                                vuln_details = self.get_vulnerability_details(vuln_id)
                                
                                if vuln_details:
                                    self.vulnerabilities.append(vuln_details)
                                else:
                                    # Если не получили детали, используем данные из поиска
                                    source = item.get('_source', {})
                                    if source:
                                        vuln = {
                                            'id': vuln_id,
                                            'title': source.get('title', 'N/A'),
                                            'cvss': source.get('cvss', {}).get('score', 0) if isinstance(source.get('cvss'), dict) else source.get('cvss', 0),
                                            'published': source.get('published', 'N/A'),
                                            'description': source.get('description', 'No description')[:200] + '...' if source.get('description') else 'No description',
                                            'type': source.get('bulletinFamily', 'cve')
                                        }
                                        self.vulnerabilities.append(vuln)
                    
                    print(f"✅ Получено {len(self.vulnerabilities)} критических уязвимостей из API")
                    return self.vulnerabilities
                else:
                    print(f"❌ Неожиданная структура ответа")
                    print(f"   Ключи в ответе: {data.keys()}")
                    raise Exception("Неверная структура ответа API")
            else:
                print(f"❌ Ошибка API: {response.status_code}")
                print(f"   Текст ошибки: {response.text}")
                raise Exception(f"API вернул ошибку {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Ошибка подключения к API: {e}")
            raise
        except Exception as e:
            print(f"❌ Неожиданная ошибка: {e}")
            raise
    
    def get_vulnerability_details(self, vuln_id):
        """
        Получение детальной информации об уязвимости
        
        Args:
            vuln_id (str): ID уязвимости (например, CVE-2024-1234)
        
        Returns:
            dict: Детальная информация об уязвимости
        """
        try:
            # Используем другой эндпоинт для получения деталей
            url = "https://vulners.com/api/v3/burp/software/"
            headers = {
                'Content-Type': 'application/json',
                'X-API-Key': self.api_key
            }
            payload = {
                "software": vuln_id
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'search' in data['data'] and data['data']['search']:
                    doc = data['data']['search'][0].get('_source', {})
                    if doc:
                        return {
                            'id': vuln_id,
                            'title': doc.get('title', 'N/A'),
                            'cvss': doc.get('cvss', {}).get('score', 0) if isinstance(doc.get('cvss'), dict) else doc.get('cvss', 0),
                            'published': doc.get('published', 'N/A'),
                            'description': doc.get('description', 'N/A')[:200] + '...' if doc.get('description') else 'N/A',
                            'type': doc.get('bulletinFamily', 'cve')
                        }
            return None
        except Exception as e:
            print(f"   Ошибка получения деталей для {vuln_id}: {e}")
            return None
    
    def correlate_threats(self):
        """
        Сопоставление угроз из логов с уязвимостями из Vulners
        """
        print("\n🔄 Сопоставление угроз с уязвимостями...")
        
        # Маппинг портов на ключевые слова для поиска
        port_keywords = {
            22: ['ssh', 'openssh', 'sshd'],
            23: ['telnet'],
            80: ['http', 'apache', 'nginx', 'web'],
            443: ['https', 'ssl', 'tls', 'apache', 'nginx'],
            1433: ['mssql', 'sql server'],
            1521: ['oracle', 'oracle database'],
            3306: ['mysql', 'mariadb'],
            5432: ['postgresql', 'postgres'],
            5900: ['vnc'],
            5800: ['vnc'],
            5060: ['sip', 'voip'],
            161: ['snmp'],
        }
        
        correlations = []
        
        # Анализируем каждый алерт
        for threat in self.threats:
            port = threat.get('dest_port')
            if port in port_keywords:
                keywords = port_keywords[port]
                
                # Ищем связанные уязвимости
                related_vulns = []
                for vuln in self.vulnerabilities:
                    title = vuln.get('title', '').lower()
                    desc = vuln.get('description', '').lower()
                    
                    for keyword in keywords:
                        if keyword in title or keyword in desc:
                            related_vulns.append(vuln)
                            break
                
                if related_vulns:
                    correlation = {
                        'src_ip': threat['src_ip'],
                        'port': port,
                        'keywords': keywords,
                        'signature': threat['signature'],
                        'related_vulnerabilities': related_vulns[:3],
                        'risk_level': 'HIGH' if threat['severity'] <= 2 else 'MEDIUM'
                    }
                    correlations.append(correlation)
                    
                    print(f"🔴 Найдена корреляция: {threat['src_ip']} сканирует порт {port} ({', '.join(keywords)})")
                    for vuln in related_vulns[:2]:
                        print(f"   • {vuln['id']}: {vuln['title']} (CVSS: {vuln['cvss']})")
        
        self.correlations = correlations
        return correlations
    
    def respond_to_threats(self):
        """
        Имитация реагирования на угрозы
        """
        print("\n🛡️ РЕАГИРОВАНИЕ НА УГРОЗЫ:")
        print("=" * 50)
        
        responses = []
        
        # Группируем угрозы по IP
        ip_threats = {}
        for threat in self.threats:
            ip = threat['src_ip']
            if ip not in ip_threats:
                ip_threats[ip] = []
            ip_threats[ip].append(threat)
        
        # Анализируем каждый IP
        for ip, threats in ip_threats.items():
            # Пропускаем локальные адреса
            if ip.startswith(('192.168.', '10.', '127.')):
                continue
                
            threat_count = len(threats)
            critical_count = sum(1 for t in threats if t['severity'] == 1)
            high_count = sum(1 for t in threats if t['severity'] == 2)
            
            print(f"\n📡 Анализ источника: {ip}")
            print(f"   Всего угроз: {threat_count}")
            print(f"   Критических: {critical_count}")
            print(f"   Высоких: {high_count}")
            
            # Принимаем меры в зависимости от количества угроз
            if threat_count >= 5 or critical_count > 0:
                action = "БЛОКИРОВКА"
                self.blocked_ips.add(ip)
                message = f"🚫 {action}: IP {ip} заблокирован (обнаружено {threat_count} угроз, {critical_count} критических)"
                print(f"   ⚡ {message}")
                
            elif threat_count >= 3:
                action = "ПРЕДУПРЕЖДЕНИЕ"
                message = f"⚠️ {action}: IP {ip} добавлен в список наблюдения ({threat_count} угроз)"
                print(f"   ⚡ {message}")
                
            else:
                action = "МОНИТОРИНГ"
                message = f"👁️ {action}: IP {ip} под наблюдением"
                print(f"   ⚡ {message}")
            
            responses.append({
                'ip': ip,
                'threat_count': threat_count,
                'critical_count': critical_count,
                'action': action,
                'message': message
            })
        
        # Итог
        print("\n" + "=" * 50)
        print(f"📋 ИТОГ РЕАГИРОВАНИЯ:")
        print(f"   Заблокировано IP: {len(self.blocked_ips)}")
        print(f"   В наблюдении: {len([r for r in responses if r['action'] == 'ПРЕДУПРЕЖДЕНИЕ'])}")
        print(f"   Под мониторингом: {len([r for r in responses if r['action'] == 'МОНИТОРИНГ'])}")
        
        self.responses = responses
        return responses
    
    def generate_report(self, output_format='csv'):
        """
        Генерация отчета в CSV или JSON формате
        
        Args:
            output_format (str): 'csv' или 'json'
        """
        print(f"\n📝 Генерация отчета в формате {output_format.upper()}...")
        
        # Подготавливаем данные для отчета
        report_data = []
        for threat in self.threats:
            report_data.append({
                'timestamp': threat['timestamp'],
                'src_ip': threat['src_ip'],
                'dest_port': threat['dest_port'],
                'signature': threat['signature'],
                'severity': threat['severity'],
                'category': threat['category'],
                'blocked': 'YES' if threat['src_ip'] in self.blocked_ips else 'NO'
            })
        
        # Создаем DataFrame
        df = pd.DataFrame(report_data)
        
        # Сохраняем в файл
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_format.lower() == 'csv':
            filename = f'threat_report_{timestamp}.csv'
            df.to_csv(filename, index=False, encoding='utf-8')
        else:
            filename = f'threat_report_{timestamp}.json'
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Отчет сохранен: {filename}")
        
        # Сохраняем также статистику
        stats_file = f'threat_stats_{timestamp}.json'
        
        # Фильтруем уязвимости для сохранения (убираем дубликаты и пустые)
        unique_vulns = []
        seen_ids = set()
        for v in self.vulnerabilities:
            if v['id'] not in seen_ids and v['id'] != 'N/A':
                seen_ids.add(v['id'])
                unique_vulns.append(v)
        
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump({
                'total_alerts': self.stats['total_alerts'],
                'unique_sources': self.stats['unique_sources'],
                'blocked_ips': list(self.blocked_ips),
                'severity_distribution': self.stats['severity_distribution'],
                'top_ips': self.stats['top_ips'],
                'responses': self.responses,
                'vulnerabilities_found': len(unique_vulns),
                'vulnerabilities': unique_vulns[:20]
            }, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Статистика сохранена: {stats_file}")
        
        return filename
    
    def create_visualization(self):
        """
        Создание графиков по результатам анализа
        """
        print("\n📊 Создание визуализации...")
        
        # Создаем фигуру с двумя подграфиками
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # График 1: Топ источников угроз
        if self.stats['top_ips']:
            ips = [ip for ip, _ in self.stats['top_ips'][:8]]
            counts = [count for _, count in self.stats['top_ips'][:8]]
            
            bars1 = ax1.bar(range(len(ips)), counts, color='red', alpha=0.7)
            ax1.set_title('Топ источников угроз', fontsize=14, fontweight='bold')
            ax1.set_xlabel('IP-адрес')
            ax1.set_ylabel('Количество оповещений')
            ax1.set_xticks(range(len(ips)))
            ax1.set_xticklabels(ips, rotation=45, ha='right')
            
            # Добавляем значения на столбцы
            for bar, count in zip(bars1, counts):
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height,
                        f'{count}', ha='center', va='bottom')
        
        # График 2: Распределение по severity
        if self.stats['severity_distribution']:
            severity_labels = {1: 'Критический', 2: 'Высокий', 3: 'Средний'}
            severities = []
            counts = []
            colors = ['darkred', 'red', 'orange']
            
            for sev in [1, 2, 3]:
                if sev in self.stats['severity_distribution']:
                    severities.append(severity_labels[sev])
                    counts.append(self.stats['severity_distribution'][sev])
            
            bars2 = ax2.bar(severities, counts, color=colors, alpha=0.7)
            ax2.set_title('Распределение угроз по критичности', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Уровень критичности')
            ax2.set_ylabel('Количество оповещений')
            
            # Добавляем значения
            for bar, count in zip(bars2, counts):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height,
                        f'{count}', ha='center', va='bottom')
        
        # Общий заголовок
        fig.suptitle(f'Анализ безопасности - {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                    fontsize=16, fontweight='bold')
        
        plt.tight_layout()
        
        # Сохраняем график
        filename = f'threat_visualization_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
        plt.savefig(filename, dpi=100, bbox_inches='tight')
        print(f"✅ График сохранен: {filename}")
        
        # Показываем график и автоматически закрываем через 3 секунды
        plt.show(block=False)
        plt.pause(3)
        plt.close()
        
        return filename


def main():
    """Основная функция выполнения задания"""
    
    print("=" * 60)
    print("🛡️  АВТОМАТИЗИРОВАННЫЙ МОНИТОРИНГ УГРОЗ")
    print("=" * 60)
    
    # ВАШ API КЛЮЧ VULNERS
    API_KEY = "J5UEG2WSGTPF0379HF0E06N6ALLMSDD2DLOJCE42LWFAOJ73YYDH3HHX44O02F2M"
    
    # Путь к файлу с логами
    log_file = "alerts-only.json"
    
    # Проверяем наличие файла
    if not os.path.exists(log_file):
        print(f"❌ Файл {log_file} не найден в текущей директории")
        print("Текущая директория:", os.getcwd())
        print("Доступные файлы:", os.listdir('.'))
        return
    
    # Создаем экземпляр монитора
    monitor = SecurityMonitor(log_file, API_KEY)
    
    try:
        # Этап 1: Загрузка логов
        print("\n" + "=" * 60)
        print("ЭТАП 1: ЗАГРУЗКА ДАННЫХ")
        print("=" * 60)
        if not monitor.load_logs():
            return
        
        # Этап 2: Анализ логов
        print("\n" + "=" * 60)
        print("ЭТАП 2: АНАЛИЗ ЛОГОВ")
        print("=" * 60)
        stats = monitor.analyze_logs()
        
        # Этап 3: Получение данных из Vulners API
        print("\n" + "=" * 60)
        print("ЭТАП 3: ПОЛУЧЕНИЕ ДАННЫХ ИЗ VULNERS API")
        print("=" * 60)
        vulns = monitor.get_vulners_data()
        
        # Этап 4: Корреляция угроз
        print("\n" + "=" * 60)
        print("ЭТАП 4: КОРРЕЛЯЦИЯ УГРОЗ")
        print("=" * 60)
        correlations = monitor.correlate_threats()
        
        # Этап 5: Реагирование на угрозы
        print("\n" + "=" * 60)
        print("ЭТАП 5: РЕАГИРОВАНИЕ")
        print("=" * 60)
        responses = monitor.respond_to_threats()
        
        # Этап 6: Формирование отчета
        print("\n" + "=" * 60)
        print("ЭТАП 6: ФОРМИРОВАНИЕ ОТЧЕТА")
        print("=" * 60)
        report_file = monitor.generate_report('csv')
        
        # Этап 7: Визуализация
        print("\n" + "=" * 60)
        print("ЭТАП 7: ВИЗУАЛИЗАЦИЯ")
        print("=" * 60)
        viz_file = monitor.create_visualization()
        
        # Итог
        print("\n" + "=" * 60)
        print("✅ РАБОТА ЗАВЕРШЕНА УСПЕШНО")
        print("=" * 60)
        print(f"📁 Созданные файлы:")
        print(f"   • Отчет: {report_file}")
        print(f"   • График: {viz_file}")
        print(f"   • Статистика: threat_stats_*.json")
        print(f"   • Заблокировано IP: {len(monitor.blocked_ips)}")
        print(f"   • Уязвимостей из API: {len(monitor.vulnerabilities)}")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ КРИТИЧЕСКАЯ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
