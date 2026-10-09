# RFP: shodan-lookup

> Generated: 2026-10-09
> Status: Approved（2026-10-09）。同日、設計確定時の独立検証パスを受けて改訂 —
> 変更点は末尾の Discussion Log「独立検証パスによる改訂」を参照。
> 実装前の実測で本文と食い違った点は「Phase 1 実測による訂正」の節にある

## 1. Problem Statement

IR では、不審な IP が見つかったときに「そのホストはインターネットから見て何を晒しているか」を確かめたくなる。
開いているポート、そこで動く製品と版、TLS 証明書、推定される脆弱性、それをいつ観測したか、の 5 つである。
フリートの lookup 群は、この問いに答える手段を持たない。asn / whois は所有者を、abuse は通報歴を、
rdns / doh は名前を返すが、サービスの姿は返さない。

Shodan はこの情報を常時スキャンして索引化しており、照会しても調査対象にはパケットが届かない。
しかし公式の手段は Python のライブラリと CLI であり、組織の是（コミュニティ製・他社製のラッパーは採用しない）にも、
lookup 群の流儀（Go 単一バイナリ、CLI 兼 MCP、構造化エラー、応答予算）にも合わない。

そこで Shodan REST API を**読み取り専用**で引く CLI 兼 MCP を、lookup 群の流儀で実装する。
対象ユーザーは組織内の IR ワークフローである。mcp-tactics 経由の Claude Code・gem-agent・lagent と、パイプで使う CLI が想定する使い方になる。
利用者は Shodan Membership を契約済みで、IR 対応時には業務でも使う。

## 2. Functional Specification

### Commands / API Surface

**MCP ツール**:

| ツール | 上流 | クレジット | Phase |
|---|---|---|---|
| `lookup_host(ip, ports?, ports_only?, refresh?)` | `GET /shodan/host/{ip}` | 消費しない | 1 |
| `get_service(ip, port, transport?, section, offset?, limit?, refresh?)` | 同上（ホスト本体から導く） | 消費しない | 1 |
| `count_services(query, facets?, refresh?)` | `GET /shodan/host/count` | 消費しない（実測） | 1 |
| `get_quota()` | `GET /api-info` | 消費しない | 1 |
| `parse_query(query)` | `GET /shodan/host/search/tokens` | 消費しない（実測） | 2 |
| `search_services(query, facets?, refresh?)` | `GET /shodan/host/search` | 0 または 1（下記） | 2 |
| `cache_status()` | — | — | 1 |
| `get_usage()` | — | — | 1 |

**件数の単位はサービス（バナー）である**。Shodan の検索の 1 件は「ある IP の、あるポートの、1 つのバナー」で、ホストではない。
条件に一致するサービスを 2 つ持つ IP は、件数で 2 と数えられ、`ip` 内訳の値も 2 になる（実測）。
ツール名を `count_services` / `search_services` とするのはこのためである。件数や内訳を「ホスト数」と読ませない。

**`lookup_host` の既定射影**:
上流 1 件は実測で 19 KB〜991 KB ある。既定の応答は数十 KB に収める。

- ホスト属性: `ip`、`org`、`isp`、`asn`、`country_code`、`city`、`hostnames`、`domains`、`os`、`tags`、`last_update`、`ports`
- `services[]`（ポート昇順、同じポートは transport 順）:
  - 識別: `port`、`transport`、`module`（`_shodan.module`）、`timestamp`
  - 製品: `product`、`version`、`cpe23`
  - `http`: status / title / server / location
  - `ssl`: subject CN / issuer CN / not_before / not_after / sha256 / versions。
    期限切れかどうかは観測時点の値ではなく、**照会時刻で計算した値**として、計算の基準時刻と一緒に出す
  - `banner`: `data` の先頭。上限は**エスケープ後のバイト数**で掛ける（既定 512 B）
  - `favicon_hash`: ピボット用。画像データ本体は出さない
  - `tags`、`vuln_count`
- `vulns[]`: CVE ID・`cvss`・`cvss_version`・`epss`・`verified` に絞る。cvss の降順（同点は CVE ID 順）で上位 N 件（既定 25）と総数を返す。
  summary と references は出さず、詳細は cve-lookup に委ねる
- `services` は既定で上限 50 件。`ports` を指定するとそのポートだけを返す。
  指定したポートが観測に無いときは、空の一覧ではなく「Shodan の観測に無い」と明記する（閉じているとは読ませない）。
  `ports_only` を真にすると services を省いて属性とポートだけを返す
- `provenance`: 出所（`shodan`）・取得時刻・キャッシュに命中したか・`doc_id`（後述）。**要求 URL は含めない**
- 何かを落としたときだけ、落とした件数と平文の注記を出す（区画ごとの省略数）
- 結果が 128 KB に近づいたら、全体を差し止める前に services を減らし、減らした件数を計上する

**`get_service`** は、1 サービスの中身を区画ごとにページングして全量まで届かせる口である。

- 区画は `banner` / `http_html` / `http_headers` / `ssl_chain` / `ssl_cert` / `vulns`（summary と references を含む。並びは CVE ID 順で固定）
- 本文は文字数で、一覧は件数で `offset` / `limit` する
- ホスト本体はキャッシュから読み、**無ければ（または TTL 切れなら）取得する**。`refresh` は取り直しを強制する
- 応答には本体のハッシュを `doc_id` として載せる。ページ送りの途中で本体が変わったことを、呼び出し側が `doc_id` の変化で知れるようにする（knowledge: mcp-server-design の文書 id）
- 同じポートに tcp と udp の両方があり（実測: 53 番）、`transport` を省いた場合は `invalid_argument` にして候補を挙げる
- 区画が返す本文は、応答予算の安全網（§3）が掛ける文字列の短縮から**名前で除外する**。全文に届かせる口が全文を返せないのは欠陥である

**`count_services`** は件数と内訳（facet）を返す。`facets` は `name[:N]` の一覧で、`ip` を含めてよい。

- `total` は一致したサービスの数、内訳の値はその値（IP など）で一致したサービスの数、と結果のフィールド名と `get_usage` に明記する
- 内訳は**上位 N 件だけ**である。全体の IP の数は返らない。`ip` 内訳はクレジットなしで「一致の多い IP の上位」を得る経路であり、
  検索に代わるピボットの主経路にするが、「IP の全一覧」とは呼ばない
- N の上限は Phase 1 で実測して決める

**`search_services`**（Phase 2）は、条件に一致するサービスを 1 ページ（最大 100 件）だけ返す。
行はコンパクト射影である（ip、port、transport、org、product、version、hostnames、timestamp、http title、vuln_count）。
クレジットの扱いは次のとおり。

- **床の検査は、消費の予測にかかわらず毎回、消費 1 とみなして行う**。`/api-info`（無消費）で残量を読み、残量 − 1 < `credit_floor`（既定 20）なら呼ばずに `credit_floor` エラーにする。
  tokens による予測が外れても床が素通りしないためである
- `/api-info` か tokens の照会が失敗したら、検索を呼ばない（fail-closed）
- 1 回の呼び出しで使うのは 1 クレジットまで。ページ 2 以降を扱うかは、Phase 2 の実測で消費の数え方を確かめてから決める
  （条件つきの 2 ページ目が 1 クレジットか 2 クレジットかは、文書からは読み取れない）
- 結果には、呼び出し**後**に `/api-info` で読み直した残量を `credits` として添える
- **呼び出し後の実際の減り方が tokens の予測と食い違ったら**、そのプロセスでは以後の検索を拒否し（`credit_mismatch`）、食い違いの内容を結果に記録する。
  予測を信じて使い続けない
- 残量としてどのフィールド（`query_credits` / `unlocked_left`）を読むか、消費が `/api-info` に反映されるまでの遅れ、同じキーを使う複数プロセスの間の競合は、Phase 2 で測る（§4）。
  測っても閉じない分（プロセス間の競合）は、理由つきの残余として AGENTS.md に書く

上流を読むツールはすべて `refresh?: bool` を受ける（`get_quota` は常に取り直す）。CLI では `--refresh` になる。

**CLI**（MCP と鏡像）:

```
shodan-lookup host <IP>... [--port N]... [--ports-only]
shodan-lookup service <IP> <PORT> [--transport tcp|udp] --section S [--offset N] [--limit N]
shodan-lookup count <QUERY> [--facet NAME[:N]]...
shodan-lookup quota
shodan-lookup tokens <QUERY>                       # Phase 2
shodan-lookup search <QUERY> [--facet NAME[:N]]... # Phase 2
shodan-lookup cache status|clear
shodan-lookup mcp
shodan-lookup version
```

上流を読むコマンド（`quota` を除く）はすべて `--refresh` と `--json` / `--raw` を受ける。
MCP の引数と CLI のフラグの対応は、実装時に対応表を 1 つ置き、CLI の概要と `usage.md` をそこから書く（web-fetch / brave-search の方式）。

### Input / Output

- 入力は引数で渡す照会である（1 件から数十件まで）。複数 IP をまとめて引くバルク照会（Corporate 限定の batch lookup）はスコープ外
- **IP はネットワークに出す前に検証する**。IPv4 / IPv6 で、グローバルユニキャストに限る。
  プライベート・ループバック・リンクローカル・文書用（TEST-NET）・CGNAT、6to4 / NAT64 / Teredo に埋め込まれた非グローバルアドレスなどは `invalid_argument` で拒否する。
  Shodan はこれらを観測しないので、照会しても必ず「索引に無い」になる。それ以上に、**内部アドレスを第三者に送らない**
  （照会はアカウントに紐づく）。上流は不正 IP と索引に無い IP の両方を 404 で返すので（実測）、ここで区別しておく
- **検索クエリにも同じゲートを掛ける**。`count_services` / `parse_query` / `search_services` のクエリから
  `ip:` / `net:` などのアドレスや CIDR を字句として取り出し、非グローバルのものを含めば送らずに拒否する。
  `parse_query` は Shodan にクエリを送るので、ローカルの検査の代わりにはならない。
  `hostname:` / `org:` に自組織の内部名を入れることは字句では判定できない。これは残余として `get_usage` に事実として書く
- ホスト名は受け付けない。名前から IP を引くのは doh-lookup の役目である（Shodan の `/dns/resolve` は使わない）
- 既定は人間向けのテキストで、`--json` を付けると JSON を stdout に出す。診断は stderr に出す
- **`--json` は完全で、上限が掛かるのは MCP の応答だけ**にする。`--raw` は上流のボディをそのまま出す
- exit 契約: 0 = 照会完了 / 1 = 上流障害または不完全な答え / 2 = 使用法エラー
- MCP ツールエラーは構造化 JSON `{code, message, details?}` で返す。コードは少なくとも次のとおり。
  - 入力: `invalid_argument` / `bad_request`（上流が 400 で拒否したクエリ）
  - 資格: `missing_api_key`（キーが無い → 設定する）/ `auth_failed`（キーが拒否された → キーを直す）。回復手順が違うので分ける
  - 否定: `not_indexed`
  - プランと残量: `plan_restricted` / `credit_floor` / `credit_mismatch`
  - 上流と通信: `rate_limited` / `endpoint_unavailable` / `upstream_error` / `timeout` / `network_error` / `decode_error`
  - その他: `response_too_large` / `internal_error`
- **MCP の引数は厳格にデコードする**。未宣言の引数は名前を挙げて `invalid_argument` にする。
  綴りを誤った `ports` が黙って無視されると、全サービスが「指定ポートの結果」に見えてしまう
- **テキスト出力では、上流由来の文字列の制御文字を見える形にエスケープする**。
  掛けるのは出力箇所ごとではなく、レンダラーに渡す前の結果全体に 1 回である（cve-lookup の訂正 22）。
  バナーと HTML は調査対象のホスト自身が書いた文字列であり、端末エスケープを素通しさせない

### Configuration

- `config.toml`（セクションつきの TOML）と環境変数 `SHODAN_LOOKUP_*` による上書き。探索順は次のとおり。
  `$XDG_CONFIG_HOME/shodan-lookup/` → `~/.config/shodan-lookup/` →（macOS のみ）`~/Library/Application Support/shodan-lookup/`。
  `cache status` は実際に読んだパスを表示し、見つからなければ探した場所を表示する
- セクション:
  - `[api]`: `key`、`base_url`
  - `[query]`: `default_services`（50）、`default_vulns`（25）、`banner_bytes`（512）
  - `[search]`: `credit_floor`（20）
  - `[cache]`: `host_ttl_hours`（12）、`count_ttl_hours`（1）、`search_ttl_hours`（24）、`dir`。TTL を 0 にするとその種類はキャッシュしない
  - `[network]`: `timeout_seconds`
  - `[limits]`: `min_interval_ms`（2000）
- API キーは `SHODAN_LOOKUP_API_KEY` で上書きできる。別名として、Shodan の利用者がよく使う変数名 `SHODAN_API_KEY` も受け付ける（gti-lookup の `VT_APIKEY` と同じ扱い）
- **`base_url` は https に限る**（テスト用の loopback の http だけ例外）。userinfo・query・fragment を持つ値は拒否する。
  キーは平文の経路に乗せない。`base_url` は操作者の設定からだけ受け取り、ツールの引数からは受け取らない
- **理解できない入力は、無視せず拒否する**。未知のセクションやキーは名前を挙げてエラーにする。
  ファイル内のキーは存在で判定し、`""` は名前を挙げて拒否する。`--config` で明示したパスが無いのもエラーである。
  数値は範囲の内側だけを受け付ける（cve-lookup の訂正 24）。
  注意: 2026-10-09 の実測用に置いたファイルは、トップレベルの `api_key` を使っている。実装後はこの形を拒否するので、
  `[api]` セクションの `key` に書き直してもらう
- **キーが無くても設定の読み込みは成功させる**（cache・MCP のハンドシェイク・`get_usage` は動く）。照会する側で検査し、無ければ `missing_api_key` を返す
- **ペーシングの既定は 2000 ms 間隔 = 文書上の上限（1 req/s）の半分**。上限はキー（アカウント）単位で、ペーシングはプロセス単位である。
  CLI のループと複数ランタイムの MCP サーバーが、同じキーから互いを見ずに消費する（cve-lookup の検証で是正した点と同じ）
- **キャッシュの単位は上流のボディそのもの**とする（キーは、エンドポイントと正規化した引数の、長さを前置したハッシュ）。
  射影・区画のページング・`--json`・`--raw` はすべてそこから導く派生ビューにする
- キャッシュしないもの: `get_quota`（アカウントの状態。gti-lookup の教訓）、`not_indexed`、劣化した結果、`parse_query`。
  `refresh` はキャッシュを読まずに取り直し、結果で上書きする
- `search_services` の TTL を長め（24 h）にするのは、同じ問いで二度クレジットを使わないためである

### External Dependencies

- Shodan REST API（`https://api.shodan.io`）のみ。認証はクエリ文字列の `key`（それ以外の渡し方は無い）
- Go 標準ライブラリのみ（`go.mod` に `require` は無い）。MCP SDK も Shodan のライブラリも使わない

## 3. Design Decisions

- **言語 = Go・依存ゼロ**: lookup 群の流儀であり、組織の是に沿う。既存の署名・notarize・tap のパイプラインに合流させる
- **骨格**: lookup 群の鏡像 `internal/{ipaddr, shodan, cache, config, engine, app, mcp}` にする。
  移植元は**パッケージごとに、兄弟の間で `git log -1 --format=%ci -- internal/<pkg>` を比べて最新を取る**。
  リポの HEAD の日付は一斉修正のコミットで揃っていて比較にならない（2026-09-23 時点で兄弟 5 本と brave-search が同じ日）。
  `internal/ipaddr` はどの兄弟にも無いので新規に書く。util-series/web-fetch の `internal/guard` の閉じた表を土台にし、
  TEST-NET の 3 帯と、6to4 / NAT64 / Teredo に埋め込まれたアドレスを足し、表の行ごとにテストする。
  どのパッケージをどこから取ったかは AGENTS.md に書く
- **名称 `shodan-lookup`**: 上流は成熟したサービスで、データは他に代替の無い Shodan 固有のものである。
  urlscan / otx / gti と同じく、ソース名を冠する
- **存在理由を守る線引き**（otx-lookup と同じ）: このツールにしか出せないのは「開放ポート・バナー・CPE・証明書・推定 CVE・観測時期」である。
  ほかのツールと衝突する機能は載せない。

  | Shodan の機能 | 担い手 | 扱い |
  |---|---|---|
  | `/dns/domain`・`/dns/resolve`・`/dns/reverse` | rdns-lookup / doh-lookup | 載せない |
  | geo・org・ASN | asn-lookup / whois-lookup | ホスト属性として並べるだけ |
  | CVE の詳細（summary / references） | cve-lookup | 既定では ID と採点だけ。`get_service` の `vulns` 区画でのみ全文 |

- **API キーと要求 URL をどの出力面にも出さない**: キーはクエリ文字列でしか渡せない。不変条件は「要求 URL は、エラー文・ログ・
  `provenance`・`details`・キャッシュキー・キャッシュファイルのどこにも現れない」である。
  - Go の `*url.Error` は URL を丸ごと文字列に含めるので、上流クライアントが返すエラーはすべて、キーを伏せた URL で包み直す
  - **リダイレクトはすべて拒否する**。Go はリダイレクトを追うとき、Location がクエリを保っていればそのまま別ホストや http へ送る。キーがクエリに載る以上、追う理由が無い
  - `base_url` は https に限る（§2）
  - タイムアウト・接続拒否・TLS 失敗・リダイレクトのすべての経路で「どの出力面にもキーが含まれない」ことをテストで固定する（knowledge: security の url.Error と資格情報のリダイレクトの節）
- **否定的な答えを取り違えさせない**:
  - 404 はステータスではなくボディの形で写す。
    `{"error": "No information available for that IP."}` は `not_indexed` にし、文言は「Shodan の索引に無い（観測されていない）」とする。
    「ポートが閉じている」「安全」とは読ませない。
    `{"error": "Invalid IP"}` は `invalid_argument` にする（ローカルのゲートと上流の判定がずれた場合。IPv6 の表記などで起こりうる）。
    どちらの形でもない 404 は `endpoint_unavailable` にする
  - **`history` を載せない理由**: Membership のキーで、データのある 2 つの IP（8.8.8.8 と 1.1.1.1。どちらも大手のエニーキャスト）に `history=true` を付けると、
    同じ 404「No information available」が返った（実測、n=2）。原因はプランの権限と推定しているが、文書では確認していない。
    権限の不足が「記録なし」に化ける偽陰性の疑いがあり、テストできない機能は出さない方針（gti-lookup の先例）と合わせて除外する
  - `vulns` が空であることは「脆弱性が無い」ではない。Shodan の脆弱性はバナーの版から推定したもので、`verified: false` は推定にすぎない（実測では 138 件すべてが false）。
    これは `get_usage` に事実として書く。逆に、推定 CVE を確定した脆弱性として見せることもしない（肯定的な答えも取り違えさせない）
  - サービスごとの `timestamp` は観測時刻であり、現在の状態ではない。射影では観測からの経過を明示する。
    ただし `timestamp` と `last_update` にはタイムゾーンの接尾辞が無い。UTC であることを文書か実測で確かめるまでは経過を計算しない（§4 Phase 1）
  - 不正なキーは 401 で、ボディは **text/plain の非 JSON** で返る（`/api-info` で実測）。これを `auth_failed` にし、JSON として読もうとして `decode_error` に化けさせない。
    検索系のエンドポイントで 401 が返ったときは、無消費の `/api-info` を読み直してキーの不正と残量・権限の不足を区別する
    （knowledge: development-process「超過は 401 で返ることがある」）
  - プラン制限（`vuln` / `tag` フィルタなど）と非 JSON の 403 の写像は、**Phase 1 で形を測るまで決めない**。
    cve-lookup の「非 JSON の 403 は `rate_limited`」は WAF の背後にある上流の写像であり、Shodan では「待てば直る」と誤った回復を促しうる。
    測れたら `plan_restricted` などを割り当て、「該当なし」にも「待て」にも化けさせない
- **応答予算は応答全体に引く**: 既定はコンパクト射影にし、大きな区画は `get_service` で区画ごとにページングする。落とした件数は、落としたときだけ計上する。
  そのうえで安全網を 2 つ置く（cve-lookup の訂正 23）。
  1 つ目: それ以外の 1000 文字を超える文字列は短縮してフィールド名を注記する。ただし `get_service` の区画が返す本文は名前で除外する。
  2 つ目: 128 KB を超える結果は全体を `response_too_large` で差し止める。`lookup_host` は差し止めの前に services を減らして計上する。
  バナーの上限はエスケープ後のバイト数で掛ける（制御文字ばかりのバナーは JSON で 6 倍に膨らみ、50 件で 128 KB を超えうる）。
  サーバー側のファイル退避はしない
- **予算を掛けるのは MCP 境界であって engine ではない**: engine は完全な射影と区画へのアクセサを返し、上限は MCP 層が掛ける。CLI の `--json` を完全なまま保つためである
- **第三者テキストはデータとして運ぶ**: バナー・HTML・証明書の subject・HTTP ヘッダは、**調査対象のホスト自身が書いた**文字列である。
  索引の中でも最も敵対的な入力になる。JSON のフィールドとしてだけ渡し、`get_usage` と `instructions` には「調査対象が書いた文字列である」という事実を書く。
  モデルへの防御指示は書かない（knowledge: mcp-server-design）。既定でバナーを短縮するのは予算のためであり、防御を名乗らない
- **出所の表示は利用者の義務を支える**: 規約 §6.7 は、Shodan の情報を自分の資料に含めるときに Shodan に帰属させ、Shodan の所有権と著作権を明示することを求める。
  IR の報告書に結果を貼る場面がこれに当たる。そのため、すべての結果の `provenance` に出所 `Shodan` を必ず載せ、CLI のテキスト出力にも出所の行を付ける。
  README と `get_usage` には、資料に含めるときの表示義務を事実として書く
- **名称と商標**: 規約 §10.2 は Shodan の商標を使う権利を与えず、§10.6 は所有者を誤認させる使い方を禁じる。
  `shodan-lookup` は対象サービスを指す記述的な使い方であり、urlscan / otx / gti の各 lookup と同じ命名である。
  README の冒頭に「Shodan®, LLC とは無関係であり、承認も受けていない」と明記する
- **クレジットを使う経路は 1 本だけにし、ツール側で守る**: `search_services` だけがクレジットを消費する。
  床の検査は予測に頼らず毎回行い、照会に失敗したら呼ばず、予測と実際が食い違ったら止まる（§2）。
  モデルが自律的に月 100 クレジットを使い切る事態を、引数の約束ではなくツール側の検査で防ぐ
  （knowledge: mcp-server-design「読み取り専用でも課金という副作用がある」）
- **OpSec**: 照会は第三者の索引を読むだけで、調査対象にはパケットが届かない。ただし照会は**利用者の Shodan アカウントに帰属する**。
  Shodan は、どの IP を・どの検索語で調べたかを知る。これは `get_usage` に書く。内部アドレスは、IP 引数でもクエリの中でも、送る前に拒否する（§2）
- **補完関係**: mcp-tactics の IP の順序は「帰属の軸」に沿っている。匿名で引ける照会を先に使い切り、利用者に帰属し課金のある照会を後に回す
  （現行: asn → tor-exit + icloud-relay → rdns → whois → abuse-lookup は課金のある唯一のものなので最後）。
  shodan-lookup も利用者に帰属し、クレジットのある照会なので、**abuse-lookup と並ぶ末尾**に置く。
  推定 CVE は cve-lookup（どれだけ悪いか・悪用中か）へ、証明書やファビコンのハッシュは `count_services` の facet でピボットする
- **明示的スコープ外**:
  - 恒久的に除外: 能動スキャン（`POST /shodan/scan`・`/shodan/scan/internet`。Shodan に対象を走査させる行為）、
    アラート・通知先・組織メンバーなど書き込み系のすべて、`/tools/myip`・`/tools/httpheaders`（自分側の情報であり調査に使わない）、
    InternetDB（無償なのは非商用に限られ、業務利用に合わない。利用者決定）
  - 現時点で除外: `history`（Membership では偽陰性の疑い）、`vuln` / `tag` フィルタ（Small Business 以上・Corporate 限定）、
    batch IP lookup（Corporate 限定）、Streaming / Trends / Exploits API、保存済みクエリのディレクトリ、データセットのダウンロード、
    `/dns/*`（§3 の線引き）

## 4. Development Plan

### Phase 1: Core

- scaffold（兄弟の鏡像。`make build` / `test` / `check`、version と help の契約、未実装コマンドは exit 2）
- `ipaddr` ゲート（IP 引数とクエリの字句の両方）、`shodan` クライアント（キーの秘匿、リダイレクト拒否、ペーシング、エラー分類、非 JSON 応答の扱い）、
  TTL キャッシュ、厳格な config、engine（射影・区画アクセサ・`doc_id`・否定的な答えの変換）
- MCP 6 本（`lookup_host` / `get_service` / `count_services` / `get_quota` / `cache_status` / `get_usage`）と、その鏡像の CLI
- オフラインテスト（httptest と、注入した Doer / clock を使う）:
  - すべての失敗経路とリダイレクトで、どの出力面にもキーが含まれないこと
  - 404 の 3 形（索引に無い / 不正 IP / API の形でない）、401 の text/plain
  - 1 MB 級ホストの射影が予算に収まること、services の上限と計上、制御文字ばかりのバナー 50 件が差し止めにならないこと
  - バナーに制御文字・双方向制御文字を含む場合
  - 内部アドレスの拒否（IP 引数とクエリの `ip:` / `net:`）、未宣言の MCP 引数の拒否
  - `get_service` の transport の曖昧さ、観測に無いポートの指定、ページ送り中の `doc_id` の変化
  - `usage.md` とコードの一致を固定するメタテスト
- **フィクスチャは手書きの合成データに限る**。実応答を取り込んでコミットしない。公開リポへのコミットは取り消せず、
  Shodan のデータの再配布条件は未確認である（§7）。実測で見た脆弱ホストの IP も記録に残さない
- **実装前に、クレジットを消費しない範囲で測る**。結果は AGENTS.md の Gotchas に日付つきで、プローブの入力の素性と一緒に記録する:
  - **索引に無いグローバルユニキャストの IP** の 404 の形（§7 の `not_indexed` は TEST-NET で採っており、ツールが送る前に拒否する帯である）
  - `history=true` をデータのある複数の IP で試し、2 件の観測が一般化できるかを確かめる
  - 各エンドポイント（host / count / tokens）の 401 の形
  - プラン制限の応答の形（`count_services` に `vuln:` を付けた場合など）と、非 JSON の 403 が来るか
  - `count` と `facets` について、不正なフィルタ・未知の facet 名・未知の引数を渡したときのふるまい（400 か、黙って無視か）
  - `facets` の N の上限と、上限超過時のふるまい
  - `timestamp` / `last_update` のタイムゾーン（UTC か）
  - IPv6 ホストの形と、ローカルゲートと上流の判定のずれ。サービス数の多いホスト（数百ポート）の大きさ
  - 429 の形は、文書化された上限を故意に超えないと測れないので測らない。429 だけを `rate_limited` として扱う

### Phase 2: Features

- `parse_query` と `search_services`（クレジット検査つき）
- **クレジットを消費する実測は、事前に消費数を伝えて了承を得てから行う**。見込みは**最大 4 クレジット**
  （条件つき 1 ページ目 1、条件つき 2 ページ目 1〜2、facet だけの検索 0〜1）。確かめること:
  - 条件つき 1 ページ目が 1 クレジットであること、条件つき 2 ページ目の消費数、facet だけの検索の消費数
  - tokens の判定が実際の消費と一致するか
  - 残量として読むフィールド（`query_credits` / `unlocked_left`）と、消費が `/api-info` に反映されるまでの遅れ
- e2e のコード化（`e2e` ビルドタグ）。既定の e2e は無消費の照会だけにし、クレジットを使う e2e は別のタグに分けて、`make e2e` では走らせない。
  **`make e2e` はキーが無ければ「実行されなかった」として失敗する**（skip で通さない。knowledge: testing「スキップするリリースゲートは、通過するゲートである」、cve-lookup の訂正 26）

### Phase 3: Release

- README.md / README.ja.md（Shodan®, LLC とは無関係である旨、Membership で使える範囲、クレジット、件数の単位がサービスであること、結果を資料に含めるときの出所表示の義務〔規約 §6.7〕、規約の読みは法的な助言ではない旨）、CHANGELOG.md、AGENTS.md
- **リリースの関門: 利用規約の再確認**。規約は 2026-10-09 に読んだ（§7）。規約は予告なく変わりうる（§20）ので、リリース前に
  `https://static.shodan.io/legal/terms.html` の sha256 を §7 の値と比べ、変わっていれば読み直して §7 を更新する。
  キャッシュを禁じる条項が現れたら、既定の TTL を 0 にする（util-series/brave-search で規約がディスクキャッシュを禁じていた先例）
- 設計確定時とリリース前に独立検証パスを通す
- `make build-all` → 署名・notarize → verify-release → homebrew-tap
- umbrella（cybersecurity-series）の submodule、org profile、nlink-web-site のカード（EN/JA）
- **mcp-tactics への追随**:
  - 存在は条件つきとする（キーのある環境にだけサーバーが在る）。SKILL.md 冒頭の「gti-lookup だけが条件つき」という書き方を、条件つきのサーバーが 2 つになる形に書き直す
  - IP の順序で、abuse-lookup と並ぶ末尾に置く（§3 の補完関係）
  - references の表（playbook）に行を足す（tests/check-fleet.sh が強制する）
  - description は現在 1,015 字で、上限 1,024 字まで 9 字しか余裕が無い。トリガ語を足す前に、どこを削るかを決める
  - フリートの台数を実リポから数え直す
- knowledge への還元: 新しい型は作らない。testing.md の既存の節「外部 API の語彙と可視範囲はライセンス階梯で変わる」に、
  `history` の実例を（Phase 1 の実測で原因が確かめられた範囲で）追記する。check-org.sh を green にする

各 Phase は独立してレビューできる。

## 5. Required API Scopes / Permissions

- Shodan API キー（Membership 以上）。OAuth・IAM は無い
- 必要な権限は、ホスト照会と件数集計（Membership で可能なことを実測済み）、検索（Membership の月 100 クエリクレジットの範囲）である
- スキャンクレジットは使わない（能動スキャンを載せないため）
- キーは利用者のアカウントの権限を持ち、照会はすべてそのアカウントに記録される。設定ファイルは 0600 で置き、リポジトリの `.gitignore` で `config.toml` を除外する

## 6. Series Placement

Series: **cybersecurity-series**
Reason: lookup 群の姉妹品で、読み取り専用の IP エンリッチメントである。シリーズの流儀にそのまま合流する
（CLI 兼 MCP、構造化エラー、TTL キャッシュ、`get_usage`、OpSec の明示）。
IP 層の「所有者・評判・名前」に「露出」を加える。

## 7. External Platform Constraints

特記の無いものは 2026-10-09 の実測（無消費の照会 17 回）で、クレジットは前後とも 100 のまま消費していない。
数値は独立検証で生の応答ファイルから数え直し、一致を確かめた。1 年後に再検証する。

- **プラン**: `/api-info` の `plan` は `"dev"`（= Membership）。クエリクレジット 100 / 月、スキャンクレジット 100 / 月、監視 16 IP（料金表どおり）。
  ログイン後の会員ページ（利用者が 2026-10-09 に PDF で提供）でも、Membership の欄に「IP lookups」の ✓ があり、
  API プランは 100 クエリ・100 スキャンクレジット / 月、使えないフィルタは `vuln` と `tag` だけと書かれている。
  Membership でホスト照会ができることの一次資料はこれである（それまでの根拠は Microsoft の連携文書という二次資料だけだった）
- **クレジット**: ホスト照会・`count`（条件つき・`facets=ip:3` を含む）・`tokens` は消費しなかった。
  検索は「条件を使う」または「2 ページ目以降」で 1 クレジット（文書）。毎月初めに戻る
- **件数の単位**: `count` の `ip` 内訳の値は、その IP で一致したサービスの数だった（一致するサービスが 80 番と 443 番の 2 つある IP の値が 2）
- **レート**: 全プラン 1 req/s（料金ページの文書）。応答にレート制限のヘッダは無かった（ヘッダは保存していないので、この点は実行時の出力による）
- **認証**: キーはクエリ文字列 `?key=` だけ（OpenAPI 定義に securitySchemes は無い）。不正なキーには 401 が返り、ボディは HTML 風の平文になる（`/api-info` でのみ確認）
- **404 は 2 つの意味で使われる**: `{"error": "Invalid IP"}` と `{"error": "No information available for that IP."}`。
  後者は TEST-NET の 192.0.2.1 で採ったもので、索引に無いグローバルユニキャストの IP では未測である
- **`history=true`**: Membership のキーで、データのある 8.8.8.8 と 1.1.1.1 の両方が 404「No information available」を返した（n=2、原因は権限と推定、文書では未確認）
- **応答の大きさ**（JSON に直列化したバイト数）:
  - 8.8.8.8 は 19 KB（3 サービス: 53/tcp、53/udp、443）
  - 1.1.1.1 は 316 KB（15 ポートに 16 サービス、1 サービスで最大 92 KB）。支配項は `http.html` の 59 KB と `http.favicon.data` の 21 KB
  - 脆弱な Apache のホストは 991 KB（4 サービス、CVE 138 件）。80 番と 443 番の 2 サービスが同じ 225 KB の `vulns` をそれぞれ持ち、計 450 KB を占める
  - `minify=true` は `data: []` を返し、475〜596 B になる
- **脆弱性の形**: ホスト直下の `vulns` は CVE ID の配列で、サービス内の `vulns` は ID をキーとする dict である（cvss / cvss_v2 / cvss_version / epss / ranking_epss / references / summary / verified）。
  summary は 1 サービスあたり 22 件が 1000 字を超え、最長 2,635 字だった
- **API の規模**: OpenAPI 定義は 37 パス・45 操作
- **利用規約**（`https://static.shodan.io/legal/terms.html`、利用者が所在を提供。2026-10-09 に全文を読んだ。
  sha256 `baf5949206cbb07d0f296cfc4dded2ba2ba9fa32c98dc2dc4d94d2b33d837102`、`Last-Modified: Sun, 10 Aug 2025 08:17:01 GMT`）。
  以下は条項の読みであって法的な助言ではない。本文は再配布しない（リポジトリに写しを置かない）:
  - **キャッシュ**: 応答の保存や保持期間を定める条項は無い。§6.5 が禁じるのは「サービスの複製・販売・転売」で、利用者の手元で一時的に応答を保持するキャッシュはこれに当たらないと読む。
    TTL つきのローカルキャッシュを維持し、ローカルキャッシュ以外にデータを置かない方針も維持する
  - **出所の表示（§6.7）**: Shodan の情報を自分の資料に含めるときは Shodan に帰属させ、所有権と著作権を明示する義務がある。§3 のとおり出所を常に結果に載せる
  - **商用利用**: 非商用に限る条項は、Academic / Research アクセスを与えられたアカウントにだけある（§6.8）。購入した Membership を非商用に限る条項は規約に無い。
    §21.2 は規約を「完全な合意」とする。料金表の「Commercial Use」の記載とは食い違いが残るが、規約の上では業務での利用を禁じる文言は見当たらない。
    利用者のアカウントが学術アップグレードではないこと（購入した Membership であること）が前提である
  - **自動化された手段（§6.3）**: 「Shodan が提供するインターフェース以外の手段で」「スクリプトやクローラなどの自動化された手段で」アクセスしないことを求める。
    API は Shodan 自身が提供し、会員ページが「スクリプトやツールから使う」ことを案内しているインターフェースなので、この条項はウェブサイトの自動取得を指すと読む。文言上の緊張は残余として記録する
  - **上限（§5.5）**: 送受信量の固定上限は、Shodan がいつでも設けうる。ペーシングとクレジット床はこれを前提にする
  - **ソフトウェアの使用許諾（§11）**: Shodan が提供するソフトウェアのリバースエンジニアリングを禁じる。このツールは公開された API 文書から書き起こし、Shodan のソフトウェアを使わないので当たらない
- InternetDB（キー不要）は、無償なのが非商用に限られ、商用には Enterprise 契約が必要である（公式ページ）。§3 のとおり採用しない

## Phase 1 実測による訂正（2026-10-09、実装前）

§4 Phase 1 の「実装前に測る」項目を、クレジットを消費しない照会 49 回（2 回の実行で 29 回と 20 回）で測った（クレジットはどちらの実行でも前後とも 100）。
上の本文と食い違う点と、本文を補う点を挙げる。実測値の正典は AGENTS.md の Gotchas。

1. **`history` を除外した理由は誤りだった**。Membership のキーで、9.9.9.9・208.67.222.222・1.0.0.1 は `history=true` に 200 を返した
   （1.0〜6.4 MB）。8.8.8.8 と 1.1.1.1 の 404 は再現したが、同じ IP を件数集計（`ip:` 条件、無消費）で引くとサービスが 2 件・15 件ある。
   404 の原因は権限ではなく、上流がその履歴を返せなかったことと読む。独立検証の M6（n=2 からの一般化）の指摘どおりだった。
   あわせて、**`history` は最新の 1000 バナーで黙って打ち切られる**（3 件とも 1000 件ちょうど。混んだホストでは 2 週間分しか遡れない）。
   最古の観測時刻は「それ以前に観測が無かった」ことを意味しない。
   `history` は Phase 1 では引き続き扱わず、搭載するかは利用者と改めて決める（搭載するなら、下の 2 の裏取りと、1000 件の打ち切りの明示が条件）
2. **「記録なし」の 404 は、上流の失敗でも返る**。§3 の「`not_indexed` にする」は、そのままでは偽陰性になりうる。
   ホスト照会が 404「No information available for that IP.」を返したら、件数集計 `ip:<アドレス>`（無消費）で裏を取る。
   0 件なら `not_indexed`、1 件以上なら `upstream_error`（「Shodan はこの IP のサービスを N 件持っているが、記録を返さなかった」）。
   裏取りに失敗したら `not_indexed` とは言わず `upstream_error` にする。追加の照会は 404 のときだけ 1 回
3. **ホスト照会はキーを検査しない**。誤ったキーでも、キーを付けなくても、`/shodan/host/{ip}` は全データを返した（`history` も同じ）。
   401 になるのは `count`・`tokens`・`/api-info` だけ（いずれも text/plain の非 JSON）。キーの誤りはホスト照会では表に出ない。
   ツールは引き続きキーを必須とし、常に送る（照会を利用者のアカウントの下で行うため）。キーの誤りに気づく手段は `get_quota` と `count_services`
4. **知らない絞り込み条件は黙って自由文になる**。`nosuchfilter:x` は 200・0 件で返り、`tokens` はそれを `nosuchfilter\:x` という文字列として扱った。
   **知らない内訳（facet）の名前は黙って無視される**（200、`facets` キーごと無い）。
   どちらも「該当なし」に化けるので、条件名と内訳名は、上流の一覧（`/shodan/host/search/filters` と `/facets`、無消費）と照合して、
   送る前に `invalid_argument` で拒否する。一覧はキャッシュする（24 時間）。照合は引用符の外の `name:` だけを字句で拾う
5. **プラン制限は「少ない件数」として現れる**。`vuln:CVE-2021-44228` は件数集計で 200・3 件だった（Log4Shell として不自然に少ない）。
   エラーにならないので、`vuln` と `tag` は送る前に `plan_restricted` で拒否する（料金表で Membership に無いと書かれている条件）。
   `tag:ics` は 83,634 件を返したが、制限の有無を外から確かめる手段が無いので同じ扱いにする
6. **構文の誤り**: 閉じていない引用符は、件数集計では 500「The search request has timed out or your query was invalid.」（時間切れと区別できない）、
   `tokens` では 400「Invalid search query」になった。引用符の釣り合いは字句の段階で検査する。空のクエリは 400「Empty search query」
7. **先頭に 0 を付けた IPv4（`008.008.008.008`）は 500「Unable to fetch information」**。ローカルのゲートが送る前に拒否する
8. **IPv6 は使える**。`2001:4860:4860::8888` と省略しない書き方の両方が同じ記録を返した。ゲートは正規形に直して送る
9. **時刻は UTC**。3 件とも、最新の観測時刻が応答ヘッダの `Date`（GMT）の 2〜30 分前だった。観測からの経過時間を計算してよい
10. **内訳の件数**: `ip:1000` は 1,000 件（39 KB）、`org:1000` は全 663 件を返した。1,000 を超える上限は測っていない。
    MCP では 1 つの内訳につき 100 件まで、CLI では 1,000 件までとする
11. 数百のサービスを持つホストは、無消費の手段では見つけられなかった（`port:65535` の上位は 1 KB 程度）。未測のまま、上限と計上で備える
12. 応答にレート制限のヘッダは無い（再確認）。応答は Cloudflare 経由

---

## Discussion Log

- **発端**: Shodan の API を使って Shodan の情報を参照する MCP サーバーを作れないか、という利用者の依頼（2026-10-09）
- **既存資料の確認**: メモリと組織内のリポジトリに、Shodan を扱った前例・却下の記録は無かった。設計の参照にしたのは
  abuse-lookup（API キーとクォータ）、urlscan-lookup（能動 / 受動の分離）、otx-lookup（存在理由の線引き・応答予算）、
  gti-lookup（ティアで機能を刈る・アカウント状態はキャッシュしない）、cve-lookup（RFP 後に判明した教訓一式）
- **一次資料**: API リファレンスと OpenAPI 定義（37 パス・45 操作）、料金ページ、クレジットの解説、InternetDB、Shodan Book を読んだ。
  Membership で無料キーとの差を述べた資料は、Microsoft の連携文書という二次資料しか見つからなかった
- **利用者の決定**: Membership は契約済みで、業務（IR 対応時）にも使う。InternetDB は入れない
- **実測を RFP の前に行った**（「クラウド依存の構想は RFP 前に利用可否を 1 回測る」の適用）。
  無消費の照会 17 回で、`history` の 404・応答の大きさ・エラーの形・無消費で IP の上位まで取れる `count` の内訳がわかった
- **検索の扱い**: 選択肢は 3 つあった（上限つきで MCP にも搭載 / CLI のみ / 搭載しない）。
  利用者は「上限つきで MCP にも搭載」を選んだ。上限は `credit_floor`（既定 20）と、1 呼び出し 1 クレジットとする
- **商用利用の論点**: 公開資料では可否を確定できなかった。ツールの設計とは切り離し、利用者側の確認事項として §7 に残す
- **名称**: ソース名を冠する `shodan-lookup` とした。上流が若く、ソースの差し替えを見込んで主題名にした cve-lookup とは事情が違う
- **独立検証パスによる改訂（2026-10-09、承認後）**: 設計確定時の検証（knowledge・ワークスペースの記録・兄弟リポの規約・実測の生ファイルとの突き合わせ）で
  high 0 / medium 8 / low 9。著者が仕分けて採否を決めた（自動適用していない）。数値の主要な根拠は著者も生ファイルで再確認した。原因の型別に:
  - **件数の単位の取り違え**（M2）: `count` はホストではなくサービスを数える。ツール名を `count_services` / `search_services` に改め、内訳は上位 N 件だけであることを明記した
  - **送ってはいけないものの経路が IP 引数だけだった**（M3・M4）: クエリ中の `ip:` / `net:` にもゲートを掛けた。
    キーの秘匿をエラー文から「全出力面」へ広げ、リダイレクトの拒否と `base_url` の https 限定を足した
  - **クレジットの床が予測に依存していた**（M1）: 毎回、消費 1 とみなして検査し、照会の失敗では呼ばず、予測と実際の食い違いで止まる形にした。消費の見込みを最大 4 に直した
  - **上流の形を測る前に写像を決め打ちしていた**（M5・M6）: `Invalid IP` の 404 を `invalid_argument` に、非 JSON の 403 の写像は実測まで保留、
    検索系の 401 は `/api-info` で原因を判別、`bad_request` を追加した。`history` は n=2・原因推定と書き直し、
    Phase 1 の実測項目（索引に無いグローバル IP、各エンドポイントの 401、不正なフィルタ・未知の引数、タイムゾーン）を足した。knowledge への還元は既存の節への追記にした
  - **`get_service` の契約の自己矛盾**（M7）: キャッシュに無ければ取得し `doc_id` で土台の変化を伝える、transport の曖昧さは拒否、観測に無いポートは明記、とした
  - **細部**（L1〜L9）: 移植元はパッケージ単位の `git log` で比べ、`ipaddr` の土台を web-fetch の表と定めた。
    安全網から区画の本文を除外し、バナーの上限をエスケープ後のバイト数にした。ペーシングを 2000 ms に、キー欠落を `missing_api_key` に、
    `make e2e` はキーが無ければ失敗に、した。mcp-tactics の順序を帰属の軸に合わせて abuse-lookup と並ぶ末尾にし、追随の項目を足した。
    CLI と MCP の鏡像を揃え、日英の食い違いを直した
  - **M8 は規約の読了で解消**（同日）: 利用者が規約の所在を提供し、全文を読んだ（§7）。キャッシュを禁じる条項は無く、
    購入した Membership を非商用に限る条項も無い。新たに、出所の表示義務（§6.7）と商標（§10）を §3 に加えた。
    リリースの関門は「規約の sha256 が変わっていないか」の再確認に改めた
- **規約に至るまで**: 公開ページのフッターにも、ログイン後の会員ページ（利用者提供の PDF）にも規約へのリンクは無かった。
  会員ページは、Membership で IP lookup と API（100 / 100 クレジット）が使えることの一次資料になった
  - 数え直しでわかった RFP 自身の誤り（照会 18 回 → 17 回、46 エンドポイント → 37 パス・45 操作、`vulns` 225 KB が 2 サービスに重複していること）は §7 と本ログを直した
