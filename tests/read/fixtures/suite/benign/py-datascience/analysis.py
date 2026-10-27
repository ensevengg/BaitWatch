"""Monthly cohort retention."""
import pandas as pd


def retention(df: pd.DataFrame, month_col: str = "month") -> pd.DataFrame:
    df = df.assign(cohort=df.groupby("user_id")[month_col].transform("min"))
    pivot = df.pivot_table(index="cohort", columns=month_col, values="user_id",
                           aggfunc="nunique")
    return pivot.div(pivot.iloc[:, 0], axis=0).round(3)


if __name__ == "__main__":
    df = pd.read_csv("events.csv")
    print(retention(df).head())
