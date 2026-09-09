<?php
/**
 * Sovereign AI Overseer — Unified Activity Log
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_Activity_Log {

    private const TABLE = 'sovauth_activity_log';

    public const CATEGORIES = [ 'sentinel', 'marketing', 'sales', 'support', 'system' ];
    public const STATUSES = [ 'info', 'pending_ai', 'blocked', 'draft', 'sent', 'failed' ];

    public static function table(): string {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    public static function create_table(): void {
        global $wpdb;
        $cc    = $wpdb->get_charset_collate();
        $table = self::table();
        $sql   = "CREATE TABLE IF NOT EXISTS {$table} (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            category    VARCHAR(30)     NOT NULL DEFAULT 'system',
            status      VARCHAR(20)     NOT NULL DEFAULT 'info',
            title       VARCHAR(255)    NOT NULL DEFAULT '',
            target      VARCHAR(255)    NOT NULL DEFAULT '',
            body        LONGTEXT        NULL,
            meta        LONGTEXT        NULL,
            event_hash  VARCHAR(64)     NULL,
            PRIMARY KEY (id),
            KEY k_category (category),
            KEY k_created  (created_at)
        ) {$cc};";
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
    }

    public static function record( string $category, string $status, string $title, string $target = '', string $body = '', array $meta = [] ): bool {
        self::create_table(); // Force creation in case the user didn't reactivate the plugin on the live site
        
        global $wpdb;
        $table = self::table();
        
        $prev_hash = $wpdb->get_var("SELECT event_hash FROM {$table} ORDER BY id DESC LIMIT 1") ?: 'GENESIS_BLOCK';
        $timestamp = current_time( 'mysql' );
        $event_hash = hash('sha256', $prev_hash . $timestamp . $category . $status . $title . $body);

        $ok = $wpdb->insert( $table, [
            'created_at' => $timestamp,
            'category'   => sanitize_key( $category ),
            'status'     => sanitize_key( $status ),
            'title'      => sanitize_text_field( $title ),
            'target'     => sanitize_text_field( $target ),
            'body'       => $body,
            'meta'       => $meta ? wp_json_encode( $meta ) : null,
            'event_hash' => $event_hash,
        ] );
        
        if (!$ok) {
            $GLOBALS['sovauth_db_error'] = $wpdb->last_error;
        }

        return (bool) $ok;
    }

    public static function query( array $args = [] ): array {
        global $wpdb;
        [ $where, $params ] = self::buildWhere( $args );

        $perPage = max( 1, min( 200, (int) ( $args['per_page'] ?? 25 ) ) );
        $page    = max( 1, (int) ( $args['page'] ?? 1 ) );
        $offset  = ( $page - 1 ) * $perPage;

        $table    = self::table();
        $params[] = $perPage;
        $params[] = $offset;

        $sql = "SELECT * FROM {$table} WHERE " . implode( ' AND ', $where ) . " ORDER BY id DESC LIMIT %d OFFSET %d";

        return $wpdb->get_results( $wpdb->prepare( $sql, $params ) );
    }

    public static function count( array $args = [] ): int {
        global $wpdb;
        [ $where, $params ] = self::buildWhere( $args );
        $table = self::table();
        $sql   = "SELECT COUNT(*) FROM {$table} WHERE " . implode( ' AND ', $where );

        if ( $params ) {
            return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
        }
        return (int) $wpdb->get_var( $sql );
    }

    public static function clear( string $category = '' ): void {
        // Intentionally disabled: audit evidence must remain append-only.
    }

    public static function export_csv(): void {
        if ( ! current_user_can( 'manage_options' ) || empty( $_REQUEST['category'] ) || ! check_admin_referer( 'sovauth_export_csv' ) ) {
            wp_die( 'Unauthorized' );
        }
        $category = sanitize_key( $_REQUEST['category'] );
        $args = [ 'category' => $category, 'per_page' => 50000 ];
        
        if ( ! empty( $_REQUEST['start_date'] ) ) {
            $args['start_date'] = sanitize_text_field( wp_unslash( $_REQUEST['start_date'] ) );
        }
        if ( ! empty( $_REQUEST['end_date'] ) ) {
            $args['end_date'] = sanitize_text_field( wp_unslash( $_REQUEST['end_date'] ) );
        }

        $entries = self::query( $args );
        
        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename=sovauth_log_' . $category . '_' . date( 'Ymd' ) . '.csv' );
        $output = fopen( 'php://output', 'w' );
        fputcsv( $output, [ 'ID', 'Date', 'Status', 'Title', 'Target', 'Body' ] );
        foreach ( $entries as $row ) {
            fputcsv( $output, [ $row->id, $row->created_at, $row->status, $row->title, $row->target, $row->body ] );
        }
        fclose( $output );
        exit;
    }

    private static function buildWhere( array $args ): array {
        $where  = [ '1=1' ];
        $params = [];

        if ( ! empty( $args['category'] ) ) {
            if ($args['category'] === 'ops') {
                $where[] = "category IN ('marketing', 'sales', 'support')";
            } else {
                $where[]  = 'category = %s';
                $params[] = sanitize_key( $args['category'] );
            }
        }
        if ( ! empty( $args['status'] ) ) {
            $where[]  = 'status = %s';
            $params[] = sanitize_key( $args['status'] );
        }
        if ( ! empty( $args['search'] ) ) {
            global $wpdb;
            $like     = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
            $where[]  = '(title LIKE %s OR target LIKE %s OR body LIKE %s)';
            $params[] = $like;
            $params[] = $like;
            $params[] = $like;
        }
        if ( ! empty( $args['start_date'] ) ) {
            $where[]  = 'created_at >= %s';
            $params[] = $args['start_date'] . ' 00:00:00';
        }
        if ( ! empty( $args['end_date'] ) ) {
            $where[]  = 'created_at <= %s';
            $params[] = $args['end_date'] . ' 23:59:59';
        }

        return [ $where, $params ];
    }

    public static function render_viewer( string $category, string $emptyText, string $nonceAction, string $search = '', string $actionField = 'sovauth_action' ): void {
        $pageParam = 'sov_log_page_' . $category;
        $page      = max( 1, (int) ( $_GET[ $pageParam ] ?? 1 ) );
        $perPage   = 25;
        $query_args = [ 'category' => $category, 'per_page' => $perPage, 'page' => $page ];
        if ($search) $query_args['search'] = $search;

        $entries   = self::query( $query_args );
        $total     = self::count( $query_args );

        $colors = [
            'blocked' => '#ff5252',
            'sent'    => '#00e676',
            'draft'   => '#ffca28',
            'failed'  => '#ff5252',
            'info'    => '#8ab4f8',
        ];

        echo '<div style="background: #1e1e1e; color: #ddd; padding: 15px; border-radius: 4px; font-family: monospace; max-height: 420px; overflow-y: auto; border: 1px solid #000; box-shadow: inset 0 0 10px #000; font-size: 13px;">';

        if ( empty( $entries ) ) {
            echo '<p style="color: #888;">&gt; ' . esc_html( $emptyText ) . '</p>';
        } else {
            foreach ( $entries as $row ) {
                $color = $colors[ $row->status ] ?? '#ddd';
                echo '<div style="margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 8px;">';
                echo '<span style="color: #888;">[' . esc_html( $row->created_at ) . ']</span> ';
                echo '<strong style="color:' . esc_attr( $color ) . ';text-transform:uppercase;">' . esc_html( $row->status ) . '</strong> ';
                echo esc_html( $row->title );
                if ( $row->target ) {
                    echo ' — <span style="color:#aaa;">' . esc_html( $row->target ) . '</span>';
                }
                if ( ! empty( $row->body ) ) {
                    if ( in_array($category, ['marketing', 'sales', 'support'], true) ) {
                        echo '<div style="margin-top:4px; font-size:11px; color:#666; font-style:italic;">(Full text saved. View in 📜 Content History)</div>';
                    } else {
                        echo '<details style="margin-top:4px;"><summary style="cursor:pointer;color:#8ab4f8;">view full content</summary>';
                        echo '<pre style="white-space:pre-wrap;color:#ddd;background:#111;padding:8px;border-radius:3px;margin-top:4px;">' . esc_html( $row->body ) . '</pre>';
                        echo '</details>';
                    }
                }
                echo '</div>';
            }
        }
        echo '</div>';

        $totalPages = (int) ceil( $total / $perPage );
        if ( $totalPages > 1 ) {
            echo '<p style="margin: 8px 0;">';
            if ( $page > 1 ) {
                echo '<a href="' . esc_url( add_query_arg( $pageParam, $page - 1 ) ) . '">&laquo; Prev</a>&nbsp;&nbsp;';
            }
            echo esc_html( sprintf( 'Page %d of %d (%d entries)', $page, $totalPages, $total ) );
            if ( $page < $totalPages ) {
                echo '&nbsp;&nbsp;<a href="' . esc_url( add_query_arg( $pageParam, $page + 1 ) ) . '">Next &raquo;</a>';
            }
            echo '</p>';
        }

        if ( $total > 0 ) {
            echo '<div style="display:flex; gap:10px; margin-top: 10px; align-items: center; flex-wrap: wrap;">';
            
            echo '<form method="get" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:flex; gap:10px; align-items:center;">';
            echo '<input type="hidden" name="action" value="sovauth_export_csv">';
            echo '<input type="hidden" name="category" value="' . esc_attr($category) . '">';
            echo '<input type="hidden" name="_wpnonce" value="' . wp_create_nonce('sovauth_export_csv') . '">';
            echo '<input type="date" name="start_date" style="line-height:normal; height:30px; font-size:13px; border:1px solid #ccc; border-radius:3px; padding:0 8px;" title="Start Date">';
            echo '<span style="color:#666;">to</span>';
            echo '<input type="date" name="end_date" style="line-height:normal; height:30px; font-size:13px; border:1px solid #ccc; border-radius:3px; padding:0 8px;" title="End Date">';
            echo '<button type="submit" class="button button-primary">⬇️ Export CSV</button>';
            echo '</form>';
            
            echo '</div>';
        }
    }
}
