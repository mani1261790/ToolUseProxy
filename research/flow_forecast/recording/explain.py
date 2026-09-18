"""Local explanation of historical artificial forecasts, never an allow decision."""


STATUS = {
    'recorded': '予測を記録済み', 'expired': '入力の有効期限切れ',
    'input_version_changed': '入力が更新されたため破棄', 'model_version_changed': 'モデル変更のため破棄',
    'model_missing': 'モデルがありません', 'model_invalid': 'モデルを検証できません',
    'input_unavailable': '元の入力を検証できません', 'input_database_failure': '入力DBを読めません',
    'timeout': '時間切れ', 'disabled': '無効化済み', 'interrupted': '中断済み',
    'out_of_domain': 'この入力への適用は未検証', 'pending': '処理待ち', 'running': '処理中',
}


def history_text(records):
    lines = ['人工データの予測履歴（現在の安全性や操作の許可を示すものではありません）']
    if not records:
        lines.append('履歴はありません。')
    for row in records:
        lines.append(f"\n{row['request_id']}\n状態: {STATUS.get(row['status'], row['status'])}")
        result = row['result']
        if result is None:
            lines.append('予測結果なし')
            continue
        forecast = result['forecast']
        probability = forecast['protected_probability']
        lines.append(f"観測位置: {result['binding']['observed_sequence']} / 予測範囲: 次の{forecast['horizon']}操作")
        lines.append(f"モデル: {forecast['model_version']} / 条件: {forecast['policy_mode']}")
        lines.append('保護情報の到達確率: ' + ('未確定' if probability is None else f'{probability:.1%}'))
        lines.append(f"未解決の確率: {forecast['unknown_probability']:.1%} / 列挙外: {forecast['other_probability']:.1%}")
        for outcome in sorted(forecast['outcomes'], key=lambda value: value['probability'], reverse=True)[:3]:
            lines.append(f"候補 {outcome['probability']:.1%}:")
            if not outcome['routes']:
                lines.append('  保護情報の経路候補なし（実際の安全確認ではありません）')
            for route in outcome['routes']:
                steps = ' → '.join(f'+{offset} {relation}/{kind}' for offset, relation, kind in route['steps'])
                lines.append(f"  {route['source']} / {route['anchor']} → {steps}")
    return '\n'.join(lines)
