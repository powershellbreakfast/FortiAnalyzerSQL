SELECT
  epid,
  devid,
  vd,
  srcip,
  devtype,
  fctuid,
  euid,
  bmp_logtype AS logtype,
  unauthuser,
  srcmac,
  osname,
  osversion,
  f_user,
  (
    CASE
      WHEN epid < 1024 THEN ipstr(srcip)
      ELSE epname
    END
  ) AS epname,
  threat_num,
  bl_count,
  cs_score,
  cs_count,
  verdict,
  ip_reversed,
  rescan,
  (
    CASE
      verdict
      WHEN 1 THEN 'Low Suspicion'
      WHEN 2 THEN 'Medium Suspicion'
      WHEN 3 THEN 'High Suspicion'
      WHEN 4 THEN 'Infected'
      ELSE 'N/A'
    END
  ) AS verdict_s,
  ack_time,
  ack_note,
  last_bl AS last_detected_time
FROM
  (
    SELECT
      epid,
      itime,
      bl_count,
      cs_score,
      cs_count,
      threat_num,
      bmp_logtype,
      last_bl,
      verdict,
      ip_reversed,
      rescan,
      srcip,
      epname,
      srcmac,
      osname,
      osversion,
      devtype,
      fctuid,
      euid,
      unauthuser,
      f_user,
      ack_note,
      ack_time,
      devid,
      vd,
      csf,
      devname
    FROM
      (
        SELECT
          tvdt.epid,
          itime,
          tvdt.bl_count,
          tvdt.cs_score,
          tvdt.cs_count,
          tvdt.threat_num,
          tvdt.bmp_logtype,
          tvdt.last_bl,
          tvdt.verdict,
          tvdt.ip_reversed,
          tvdt.rescan,
          (
            CASE
              WHEN tvdt.epid > 1024 THEN tep.epip
              ELSE tvdt.srcip
            END
          ) AS srcip,
          tep.epname,
          tep.mac AS srcmac,
          tep.osname,
          tep.osversion,
          tep.epdevtype AS devtype,
          teu.fctuid,
          teu.euid,
          teu.unauthuser,
          (
            CASE
              WHEN teu.euid <= 1024 THEN ipstr(tvdt.srcip)
              ELSE teu.euname
            END
          ) AS f_user,
          tack.ack_note,
          (
            CASE
              WHEN (
                tvdt.ack_time_max = 0
                OR tvdt.ack_time_min = 0
              ) THEN NULL
              ELSE tvdt.ack_time_max
            END
          ) AS ack_time,
          tdev.devid,
          tdev.vd,
          tdev.csf,
          tdev.devname,
          tdev.devgrps
        FROM
          (
            SELECT
              epid,
              srcip,
              min(day_st) AS itime,
              array_length(intarr_agg(threatid), 1) AS threat_num,
              intarr_agg(dvid) AS dvid,
              sum(bl_count) AS bl_count,
              max(cs_score) AS cs_score,
              sum(cs_count) AS cs_count,
              max(last_bl) AS last_bl,
              max(ack_time) AS ack_time_max,
              min(ack_time) AS ack_time_min,
              bit_or(bmp_logtype) AS bmp_logtype,
              max(verdict) AS verdict,
              max(ip_reversed) AS ip_reversed,
              max(rescan) AS rescan
            FROM
              (
                (
                  SELECT
                    epid,
                    srcip,
                    day_st,
                    ack_time,
                    threatid,
                    dvid,
                    bl_count,
                    cs_score,
                    cs_count,
                    last_bl,
                    bmp_logtype,
                    verdict,
                    (
                      CASE
                        WHEN ioc_flags & 2 > 0 THEN 1
                        ELSE 0
                      END
                    ) AS ip_reversed,
                    (
                      CASE
                        WHEN ioc_flags & 1 > 0 THEN 1
                        ELSE 0
                      END
                    ) AS rescan
                  FROM
                    $ADOMTBL_PLHD_IOC_VERDICT
                    /*verdict table*/
                  WHERE
                    day_st >= $start_time
                    AND day_st <= $end_time
                    /*time filter*/
                )
                UNION ALL
                (
                  SELECT
                    epid,
                    srcip,
                    day_st,
                    ack_time,
                    threatid,
                    dvid,
                    bl_count,
                    cs_score,
                    cs_count,
                    last_bl,
                    bmp_logtype,
                    verdict,
                    (
                      CASE
                        WHEN ioc_flags & 2 > 0 THEN 1
                        ELSE 0
                      END
                    ) AS ip_reversed,
                    (
                      CASE
                        WHEN ioc_flags & 1 > 0 THEN 1
                        ELSE 0
                      END
                    ) AS rescan
                  FROM
                    $ADOMTBL_PLHD_INTERIM_IOC_VERDICT
                    /*verdict intrim table*/
                  WHERE
                    day_st >= $start_time
                    AND day_st <= $end_time
                    /*time filter*/
                    AND verdict > 0
                )
              ) tvdt_int
            GROUP BY
              epid,
              srcip
          ) tvdt
          INNER JOIN
          /*end points*/
          $ADOM_ENDPOINT AS tep ON tvdt.epid = tep.epid
          LEFT JOIN
          /*end user*/
          (
            SELECT
              epid,
              euname,
              fctuid,
              euid,
              unauthuser
            FROM
              (
                SELECT
                  epid,
                  eu.euid,
                  euname,
                  fctuid,
                  euname AS unauthuser,
                  row_number() OVER (
                    PARTITION BY epid
                    ORDER BY
                      (
                        (
                          CASE
                            WHEN fctuid IS NULL THEN 0
                            ELSE 1
                          END
                        ),
                        lastactive
                      ) DESC
                  ) nth
                FROM
                  $ADOM_ENDUSER eu
                  /*end user*/
,
                  $ADOM_EPEU_DEVMAP AS map
                  /*epeu dev_map*/
                WHERE
                  eu.euid = map.euid
                  AND eu.euid > 1024
              ) eum
            WHERE
              nth = 1
          ) teu ON tvdt.epid = teu.epid
          LEFT JOIN
          /*ack table*/
(
            SELECT
              epid,
              srcip,
              ack_time,
              ack_note
            FROM
              (
                SELECT
                  epid,
                  srcip,
                  ack_time,
                  ack_note,
                  row_number() OVER (
                    PARTITION BY epid,
                    srcip
                    ORDER BY
                      ack_time DESC
                  ) AS ackrank
                FROM
                  ioc_ack
                WHERE
                  adomoid = $adom_oid
              ) rankqry
            WHERE
              ackrank = 1
          ) tack ON tvdt.epid = tack.epid
          AND (
            (
              tvdt.srcip IS NULL
              AND tack.srcip IS NULL
            )
            OR tvdt.srcip = tack.srcip
          )
          LEFT JOIN devtable_ext tdev ON tdev.dvid = tvdt.dvid [ 1 ]
        WHERE
          tvdt.dvid && (
            SELECT
              array_agg(dvid)
            FROM
              devtable_ext
            WHERE
              $filter-drilldown
          )
      ) tioc
  ) t
ORDER BY
  threat_num DESC
