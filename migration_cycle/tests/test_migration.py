from migration_cycle import migration_cycle as mc
import unittest


class TestMigrationCycleCLI(unittest.TestCase):

    def test_cli_logger(self):
        hostname = "test_cli_logger"
        logger = mc.cli_logger(hostname)
        self.assertEqual(hostname, logger.name)

    def test_validate_scheduling_days(self):
        # valid data
        w_days = "0,1,2,3,4"
        self.assertEqual(w_days, mc.validate_scheduling_days(w_days))

        # invalid data
        w_days = "0,1,2,3,4,5,6,7"
        with self.assertRaises(Exception) as context:
            mc.validate_scheduling_days(w_days)

        self.assertTrue('scheduling days must be in 0-6'
                        in str(context.exception))

    def test_validate_scheduling_hours(self):
        # default behaviour
        hour = "-1"
        output = mc.validate_scheduling_hours(hour)
        self.assertEqual(output, -1)

        # range of 0-23
        hour = "8"
        output = mc.validate_scheduling_hours(hour)
        self.assertEqual(output, 8)

        # not in range of 0-23
        hour = "72"
        with self.assertRaises(Exception) as context:
            mc.validate_scheduling_hours(hour)

        self.assertTrue('scheduling hours must be in 0-23'
                        in str(context.exception))

    def test_cli_execution_no_args(self):
        self.args = []
        with self.assertRaises(SystemExit) as cm:
            mc.cli_execution(self.args)
        self.assertEqual(cm.exception.code, None)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
