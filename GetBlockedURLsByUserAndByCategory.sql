SELECT
  usersrc,
  catdesc,
  hostname,
  sum(requests) AS requests
FROM
  ###(
    SELECT
      COALESCE(nullifna(`user`), ipstr(`srcip`)) AS usersrc,
      euid,
      hostname,
      catdesc,
      ACTION,
      count(*) AS requests
    FROM
      $log
    WHERE
      $filter
    GROUP BY
      usersrc,
      euid,
      hostname,
      catdesc,
      ACTION
    ORDER BY
      requests DESC
  )### t1
WHERE
  catdesc IS NOT NULL
  AND hostname IS NOT NULL
  AND ACTION = 'blocked'
GROUP BY
  usersrc,
  catdesc,
  hostname
ORDER BY
  requests DESC
