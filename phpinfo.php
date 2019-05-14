<?php


class phpinfo
{

    /**
     * phpinfo constructor.
     */
    function __construct()
    {
    }

    /**
     * @return array
     */
    static public function phpinfo_general()
    {
        return self::_parse_phpinfo(INFO_GENERAL);
    }

    /**
     * @return array
     */
    static public function phpinfo_configuration()
    {
        return self::_parse_phpinfo(INFO_CONFIGURATION);
    }

    /**
     * @return array
     */
    static public function phpinfo_environment()
    {
        return self::_parse_phpinfo(INFO_ENVIRONMENT);
    }

    /**
     * @return array
     */
    static public function phpinfo_variable()
    {
        return self::_parse_phpinfo(INFO_VARIABLES);
    }

    /**
     * @return array
     */
    static public function phpinfo_modules()
    {
        $cat = "None";
        $info_arr = [];
        ob_start();
        phpinfo(INFO_MODULES);
        $info_lines = explode("\n", strip_tags(ob_get_clean(), "<tr><td><h2>"));
        foreach ($info_lines as $line) {
            if (preg_match("~<h2>(.*)</h2>~", $line, $title)) $cat = $title[1];
            if
            (
                preg_match("~<tr><td[^>]+>([^<]*)</td><td[^>]+>([^<]*)</td></tr>~", $line, $val)
                OR
                preg_match("~<tr><td[^>]+>([^<]*)</td><td[^>]+>([^<]*)</td><td[^>]+>([^<]*)</td></tr>~", $line, $val)
            )
                $info_arr[$cat][trim($val[1])] = trim(str_replace(';', '; ', $val[2]));
        }
        return $info_arr;
    }

    /**
     * @return array
     */
    static public function phpinfo_credits()
    {
        return self::_parse_phpinfo(INFO_CREDITS);
    }

    /**
     * @return string
     */
    static public function phpinfo_license()
    {
        ob_start();
        phpinfo(INFO_LICENSE);
        $info_lines = explode("\n", strip_tags(ob_get_clean(), "<tr><td><h2>"));
        return implode('. ', array($info_lines[28], $info_lines[30], $info_lines[32]));

    }

    /**
     * @return array
     */
    static public function all()
    {
        $res = array();
        $res["General"] = self::phpinfo_general();
        $res["Configuration"] = self::phpinfo_configuration();
        $res["Environment"] = self::phpinfo_environment();
        $res["Variable"] = self::phpinfo_variable();
        $res["Modules"] = self::phpinfo_modules();
        $res["Credits"] = self::phpinfo_credits();
        $res["License"] = self::phpinfo_license();
        return $res;
    }

    /**
     * @param $type
     * @return array
     */
    static private function _parse_phpinfo($type)
    {
        $info_arr = [];
        ob_start();
        phpinfo($type);
        $info_lines = explode("\n", strip_tags(ob_get_clean(), "<tr><td><h2>"));
        foreach ($info_lines as $line) {
            if
            (
                preg_match("~<tr><td[^>]+>([^<]*)</td><td[^>]+>([^<]*)</td></tr>~", $line, $val)
                OR
                preg_match("~<tr><td[^>]+>([^<]*)</td><td[^>]+>([^<]*)</td><td[^>]+>([^<]*)</td></tr>~", $line, $val)
            )
                $info_arr[trim($val[1])] = trim(str_replace(';', '; ', $val[2]));
        }
        return $info_arr;
    }

}